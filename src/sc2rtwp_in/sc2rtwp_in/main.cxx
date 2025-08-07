//module;

#include <common/win_headers.h>
#include <malloc.h>

import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.debug.veh;
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

u64 imagebase = 0;
void decodeAntidebug(u64& a1, u64& a2)
{
	const u64 c = 0xF3791823EBD0BA08;
	a2 = std::rotr(c, 12) - a2;
	a1 ^= ~imagebase ^ c;
}

struct AntidebugCrash
{
	u64 f0;
	u64 crashTick;
	u64 f10;
	u32 f18;
	u32 reason;
	u64 f20;
	u64 f28;
};
//bool operator!=(const AntidebugCrash& l, const AntidebugCrash& r) { return memcmp(&l, &r, sizeof(AntidebugCrash)) != 0; }
bool operator!=(const AntidebugCrash& l, const AntidebugCrash& r) { return memcmp(&l.f0 + 1, &r.f0 + 1, sizeof(AntidebugCrash) - 8) != 0; } // ignore f0, it just changes all the time..

u64* xorredCrashState = nullptr;
AntidebugCrash getCrashState()
{
	AntidebugCrash res = {};
	auto outPtr = &res.f0;
	u64 h1 = 0x96478FAEECCF46AE, h2 = xorredCrashState[6];
	decodeAntidebug(h1, h2);
	for (int i = 0; i < 6; ++i)
	{
		outPtr[i] = xorredCrashState[i] ^ (std::rotr(h1, 11) - h2);
		h1 = std::rotr(xorredCrashState[i], 11) - h2;
	}
	return res;
}

AntidebugCrash lastCrash = {};
int tickId = 0;
bool updateLastCrash()
{
	auto tickIndex = tickId++;
	auto prevCrash = lastCrash;
	lastCrash = getCrashState();
	if (lastCrash != prevCrash)
	{
		Log::msg("Crash changed at frame {}: at {} (in {} ms), reason={}, fields={:016X} {:016X} {:08X} {:016X} {:016X}", tickIndex, lastCrash.crashTick, (int)(lastCrash.crashTick - GetTickCount()), lastCrash.reason, lastCrash.f0, lastCrash.f10, lastCrash.f18, lastCrash.f20, lastCrash.f28);
	}
	return false;
}

void checkCrashState(void* spinlock)
{
	if (*reinterpret_cast<u32*>(spinlock) != 0)
		return; // just entered spinlock, wait
	auto state = getCrashState();
	if (state.reason != lastCrash.reason)
	{
		Log::msg("Starting to crash");
		Log::stack();
	}
}

void* roundToPage(void* ptr)
{
	return (void*)((u64)ptr & ~0xFFF);
}

void protectPage(void* ptr, DWORD protection, int npages = 1)
{
	DWORD old;
	auto res = VirtualProtect(roundToPage(ptr), 4096 * npages, protection, &old);
	if (!res)
		Log::msg("Failed to set protection for {}: {}", ptr, GetLastError());
}

void growStack(int extraPages)
{
	auto origStackLimit = NtCurrentTeb()->Reserved1[2];
	do {
		alloca(4096);
	} while (NtCurrentTeb()->Reserved1[2] == origStackLimit || extraPages--);
}

bool protectStack()
{
	auto origStackLimit = NtCurrentTeb()->Reserved1[2];
	Log::msg("Trying to protect stack for thread {}: {}", GetCurrentThreadId(), origStackLimit);
	growStack(4);
	auto currStackLimit = NtCurrentTeb()->Reserved1[2];
	protectPage(currStackLimit, PAGE_READONLY, 5);
	Log::msg("Protect stack: orig={}, curr={}, end={}", origStackLimit, currStackLimit, NtCurrentTeb()->Reserved1[1]);
	return true;
}

void processTriggerHook(u32 id)
{
	Log::msg("Trigger: {}", id);
}

void init()
{
	auto& app = App::instance();
	Log::msg("Hello from injected; imagebase = {}", static_cast<void*>(app.hooker().imagebase()));
	app.installHooks();

	auto& debugVEH = DebugVEH::instance();
	debugVEH.install();

	auto& hookAlloc = app.hooker();

	// TODO: this is an imagebase from from the dump i've been using for reversing; replace with sigs...
	const auto segbase = 0x7FF6AE4D0000;

	imagebase = (u64)hookAlloc.imagebase();
	xorredCrashState = (u64*)(imagebase + (0x7FF6B1EC07F8 - segbase));
	updateLastCrash();
	debugVEH.setWriteBreakpoint(xorredCrashState + 7, checkCrashState); // set on spinlock

	app.addTickCallback(protectStack);
	app.addTickCallback(updateLastCrash);

	// skip hash checks
	auto antidebugState = *(char**)(imagebase + (0x7FF6B1EBEFC8 - segbase));
	auto& xorredNumPageHashes = *(u32*)(antidebugState + 0x100);
	auto nphKey1 = 0x255A95D456AE37AA;
	auto nphKey2 = *(u64*)(imagebase + (0x7FF6B1EC0216 - segbase));
	auto nphKey = nphKey1 - std::rotr(nphKey2, 12);
	Log::msg("Num hashed pages = {:X} == {:X} ^ ({:X} - ({:X} >>> 12))", xorredNumPageHashes ^ nphKey, xorredNumPageHashes, nphKey1, nphKey2);
	xorredNumPageHashes = 1 ^ nphKey;

	//patchHashDiff(curbase, 0x15BAA80, 0x15BB54F);
	//patchHashDiff(curbase, 0x16497A0, 0x1649700);
	//*(uint16_t*)(curbase +0x15BAA10) = 0x9090;

	// avoid segment checks: replace first two (code and data) with last one
	u64* antidebugSegment = (u64*)(imagebase + (0x7FF6AE597AE4 - segbase));
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
