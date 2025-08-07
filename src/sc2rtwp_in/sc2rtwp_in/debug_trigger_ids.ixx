export module injected.debug.trigger_ids;

import std;
import common;
import injected.logger;
import injected.app;

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
	}

private:
	static void processTriggerHook(u32 id)
	{
		Log::msg("Trigger: {}", id);
	}
};
