module;

#include <common/win_headers.h>

export module injected.debug.delayed_crash;

import std;
import common;
import injected.logger;
import injected.app;
import injected.cs.antitamper;
import injected.debug.veh;

// this utility provides two kinds of debugging, these can be activated independently:
// - a function executed every tick to track delayed crash state changes (if needed, this can be turned into antidebug utility to immediately clear incoming crash - but for now we instead prevent them from being triggered at all)
// - a breakpoint on crash state changes - this simplifies tracking down antidebug code by logging the stack directly
export class DebugDelayedCrash
{
public:
	static DebugDelayedCrash& instance()
	{
		static DebugDelayedCrash inst;
		return inst;
	}

	void installTickMonitor()
	{
		updateLastState();
		App::instance().addTickCallback([this]() { return updateLastState(); });
	}

	void installChangeMonitor()
	{
		DebugVEH::instance().setWriteBreakpoint(&AntitamperAccess::instance().state()->delayedCrashSpinlock, [this](void* spinlock) {
			if (*reinterpret_cast<u32*>(spinlock) != 0)
				return; // just entered spinlock, wait
			auto state = AntitamperAccess::instance().decodeDelayedCrashState();
			if (state.reason != mCurState.reason)
			{
				Log::msg("Starting to crash");
				Log::stack();
			}
		});
	}

private:

	// always returns false - used as a tick function
	bool updateLastState()
	{
		auto frameIndex = mNextFrameId++;
		auto prev = mCurState;
		mCurState = AntitamperAccess::instance().decodeDelayedCrashState();
		if (memcmp(&mCurState.f0 + 1, &prev.f0 + 1, sizeof(DelayedCrashState) - 8) != 0) // ignore f0, it just changes all the time..
		{
			Log::msg("Delayed crash state changed at frame {}: at {} (in {} ms), reason={}, fields={:016X} {:016X} {:08X} {:016X} {:016X}", frameIndex,
				mCurState.crashTick, (int)(mCurState.crashTick - GetTickCount()), mCurState.reason, mCurState.f0, mCurState.f10, mCurState.f18, mCurState.f20, mCurState.f28);
		}
		return false;
	}

private:
	int mNextFrameId = 0;
	DelayedCrashState mCurState = {};
};
