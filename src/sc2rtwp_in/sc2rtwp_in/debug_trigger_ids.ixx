export module injected.debug.trigger_ids;

import std;
import common;
import injected.logger;
import injected.app;
import injected.debug.veh;

// utility to hook trigger execution and dump out ids
// usecase is to add a trigger in a test map, observe the id, and find the corresponding handler code
export class DebugTriggerIds
{
public:
	static DebugTriggerIds& instance()
	{
		static DebugTriggerIds inst;
		return inst;
	}

	void install()
	{
		auto imagebase = App::instance().imagebase();

		// hook switch-case on process trigger
		// here we have a large junk region right after call (so we don't have to preserve volatile registers); r13d contains id
		char* processTriggerJumpFrom = imagebase + 0x25DD310;
		char* processTriggerJumpTo = imagebase + 0x25DD34C;
		const unsigned char processTriggerPatch[] = {
			/* 0x00 */ 0x44, 0x89, 0xE9, // mov ecx, r13d
			/* 0x03 */ 0xFF, 0x15, 0x05, 0x00, 0x00, 0x00, // call [rip+5] ; 0xE
			/* 0x09 */ 0xE9, 0x00, 0x00, 0x00, 0x00, // jmp ...
		};
		std::memcpy(processTriggerJumpFrom, processTriggerPatch, sizeof(processTriggerPatch));
		*reinterpret_cast<u32*>(processTriggerJumpFrom + sizeof(processTriggerPatch) - 4) = processTriggerJumpTo - processTriggerJumpFrom - sizeof(processTriggerPatch);
		*reinterpret_cast<void**>(processTriggerJumpFrom + sizeof(processTriggerPatch)) = processTriggerHook;

		oriTriggerUnitSetPropertyFixed = App::instance().hooker().hook(0x9B9780, 0x10, hookTriggerUnitSetPropertyFixed);
		oriTriggerUnitGetPropertyFixed = App::instance().hooker().hook(0x9A8590, 0x14, hookTriggerUnitGetPropertyFixed);

		auto* unitLookup = imagebase + 0x3B80B40;
		auto findUnit = reinterpret_cast<char* (*)(void*, u32)>(imagebase + 0x6603D0);
		auto testUnit = findUnit(unitLookup, 1);
		Log::msg("Unit {}: #{}, max speed={}, accel={}", (void*)testUnit, *(u32*)(testUnit), *(u32*)(testUnit + 0xFC), *(u32*)(testUnit + 0x100));
		DebugVEH::instance().setWriteBreakpoint(testUnit + 0x74, [](void* speedX) {
			Log::msg("Speed changed to {}", *(u32*)speedX);
			Log::stack();
		});
	}

private:
	static void processTriggerHook(u32 id)
	{
		Log::msg("[{}] Trigger: {}", std::chrono::system_clock::now(), id);
	}

	void (*oriTriggerUnitSetPropertyFixed)(u32*, u32, int) = nullptr;
	static void hookTriggerUnitSetPropertyFixed(u32* unitId, u32 propId, int propVal)
	{
		Log::msg("[{}] UnitSetPropertyFixed({}, {}, {})", std::chrono::system_clock::now(), *unitId, propId, propVal);
		instance().oriTriggerUnitSetPropertyFixed(unitId, propId, propVal);
	}

	int (*oriTriggerUnitGetPropertyFixed)(u32*, u32, bool) = nullptr;
	static int hookTriggerUnitGetPropertyFixed(u32* unitId, u32 propId, bool curr)
	{
		Log::msg("[{}] UnitGetPropertyFixed({}, {}, {})", std::chrono::system_clock::now(), *unitId, propId, curr);
		return instance().oriTriggerUnitGetPropertyFixed(unitId, propId, curr);
	}
};
