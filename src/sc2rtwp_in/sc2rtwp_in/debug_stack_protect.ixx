module;

#include <common/win_headers.h>
#include <malloc.h>

export module injected.debug.stack_protect;

import std;
import common;
import injected.logger;
import injected.app;

// one of the way SC2 antidebug crashes the game when it detects tampering is by filling the stack with junk before causing AV
// this makes the stack trace at the exception time useless
// this utility prevents that by growing a stack by a few pages and write-protecting them, so that AV is triggered before stack is trashed
// this needs to be done in the context of the main thread - we solve that using one-shot tick function
export class DebugStackProtect
{
public:
	static DebugStackProtect& instance()
	{
		static DebugStackProtect inst;
		return inst;
	}

	void installMainThread()
	{
		App::instance().addTickCallback(protectStack);
	}

private:
	static void growStack(void* intendedLimit)
	{
		auto origStackLimit = NtCurrentTeb()->Reserved1[2];
		while (NtCurrentTeb()->Reserved1[2] > intendedLimit)
		{
			alloca(4096);
		}
	}

	static bool protectStack()
	{
		constexpr size_t Size = 5 * 4096;
		auto origStackLimit = NtCurrentTeb()->Reserved1[2];
		void* intendedStackLimit = static_cast<char*>(origStackLimit) - Size;
		Log::msg("Trying to protect stack for thread {}: {} -> {}", GetCurrentThreadId(), origStackLimit, intendedStackLimit);
		growStack(intendedStackLimit);
		auto currStackLimit = NtCurrentTeb()->Reserved1[2];
		Process::protectMemoryFor(currStackLimit, PAGE_READONLY, Size);
		Log::msg("Protect stack: orig={}, curr={}, end={}", origStackLimit, currStackLimit, NtCurrentTeb()->Reserved1[1]);
		return true;
	}
};
