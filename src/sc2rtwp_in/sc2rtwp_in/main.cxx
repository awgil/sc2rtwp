#include <common/win_headers.h>

import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.debug.veh;
import injected.debug.stack_protect;
import injected.debug.delayed_crash;
import injected.game.slowmode;

void logHashDiff(u64 index, u32* table, u32 hash, u32 expected)
{
	auto& entry = table[1 + 2 * index];
	auto hash_const = expected ^ entry;
	Log::msg("hash difference found at #{:X} + {:X}: current={:08X}, expected={:08X}, hashed_expected={:08X}, hash_const={:08X}, f0={:08X}, e0={:08X}, table={}", index, 0x1000, hash, expected, entry, hash_const, table[0], table[1], static_cast<void*>(table));
	entry = hash ^ hash_const;
}

void patchHashDiff(char* imagebase, u64 diffFoundRVA, u64 jumpRVA)
{
	// assumption: rbx = current hash, rax = expected hash, r13 = index, rdi = table
	const unsigned char hashPatch[] = { 0x4C, 0x89, 0xE9, 0x48, 0x89, 0xFA, 0x41, 0x89, 0xD8, 0x41, 0x89, 0xC1, 0xFF, 0x15, 0x05, 0x00, 0x00, 0x00, 0xE9 };
	memcpy(imagebase + diffFoundRVA, hashPatch, sizeof(hashPatch));
	*(u32*)(imagebase + diffFoundRVA + sizeof(hashPatch)) = jumpRVA - diffFoundRVA - sizeof(hashPatch) - 4;
	*(void**)(imagebase + diffFoundRVA + sizeof(hashPatch) + 4) = logHashDiff;
}

void processTriggerHook(u32 id)
{
	Log::msg("Trigger: {}", id);
}

void init()
{
	auto& app = App::instance();
	Log::msg("Hello from injected; imagebase = {}", static_cast<void*>(app.imagebase()));
	app.installHooks();

	// debug stuff - should be possible to disable completely and still run this
	DebugVEH::instance().install();
	DebugStackProtect::instance().installMainThread();
	DebugDelayedCrash::instance().installTickMonitor();
	DebugDelayedCrash::instance().installChangeMonitor();

	auto& hookAlloc = app.hooker();

	// TODO: this is an imagebase from from the dump i've been using for reversing; replace with sigs...
	const auto segbase = 0x7FF6AE4D0000;

	// skip hash checks
	auto antidebugState = *(char**)(hookAlloc.imagebase() + (0x7FF6B1EBEFC8 - segbase));
	auto& xorredNumPageHashes = *(u32*)(antidebugState + 0x100);
	auto nphKey1 = 0x255A95D456AE37AA;
	auto nphKey2 = *(u64*)(hookAlloc.imagebase() + (0x7FF6B1EC0216 - segbase));
	auto nphKey = nphKey1 - std::rotr(nphKey2, 12);
	Log::msg("Num hashed pages = {:X} == {:X} ^ ({:X} - ({:X} >>> 12))", xorredNumPageHashes ^ nphKey, xorredNumPageHashes, nphKey1, nphKey2);
	xorredNumPageHashes = 1 ^ nphKey;

	//patchHashDiff(curbase, 0x15BAA80, 0x15BB54F);
	//patchHashDiff(curbase, 0x16497A0, 0x1649700);
	//*(uint16_t*)(curbase +0x15BAA10) = 0x9090;

	// avoid segment checks: replace first two (code and data) with last one
	u64* antidebugSegment = (u64*)(hookAlloc.imagebase() + (0x7FF6AE597AE4 - segbase));
	antidebugSegment[0] = antidebugSegment[3] = antidebugSegment[12];
	antidebugSegment[1] = antidebugSegment[4] = antidebugSegment[13];
	antidebugSegment[2] = antidebugSegment[5] = antidebugSegment[14];

	// skip checks in the antidebug thread, which validate tampering for antidebug state and pagehash map
	if (*(u32*)(antidebugState + 0xE80))
		Log::msg("Warning: bad time to inject, antidebug thread is mid pagehash checks...");
	Hooker::patchJumpToUnconditional(hookAlloc.imagebase() + (0x7FF6AE6D6C63 - segbase)); // page hash
	Hooker::patchJumpToUnconditional(hookAlloc.imagebase() + (0x7FF6AE6D721E - segbase)); // state hash

	// hook switch-case on process trigger
	// here we have a large junk region right after call (so we don't have to preserve volatile registers); r13d contains id
	//char* processTriggerJumpFrom = imagebase + (0x7FF6B0AAD310 - segbase);
	//char* processTriggerJumpTo = imagebase + (0x7FF6B0AAD34C - segbase);
	//const unsigned char processTriggerPatch[] = { 0x44, 0x89, 0xE9, 0xFF, 0x15, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00 };
	//memcpy(processTriggerJumpFrom, processTriggerPatch, sizeof(processTriggerPatch));
	//*(u32*)(processTriggerJumpFrom + sizeof(processTriggerPatch) - 4) = processTriggerJumpTo - processTriggerJumpFrom - sizeof(processTriggerPatch);
	//*(void**)(processTriggerJumpFrom + sizeof(processTriggerPatch)) = processTriggerHook;

	GameSlowmode::install(app);
	Log::msg("Injection done, resuming game...");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		init();
	}
	return true;
}
