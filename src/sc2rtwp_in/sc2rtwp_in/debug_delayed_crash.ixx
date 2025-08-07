module;

#include <common/win_headers.h>

export module injected.debug.delayed_crash;

import std;
import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.debug.veh;

// this is immediately followed by encryption key (u64) and then by spinlock (u32)
struct CrashState
{
	u64 f0; // i don't think it's actually meaningful, it is not read anywhere as far as i can see, and changes randomly every time it's reencoded
	u64 crashTick; // if GetTickCount() returns >= this value, we crash
	u64 f10; // crash will happen if this is non-zero, usually some small int
	u32 f18;
	u32 reason;
	u64 f20; // crash will happen if this is non-zero, some sort of a hash?
	u64 f28;
};
//bool operator!=(const CrashState& l, const CrashState& r) { return memcmp(&l, &r, sizeof(CrashState)) != 0; }
bool operator!=(const CrashState& l, const CrashState& r) { return memcmp(&l.f0 + 1, &r.f0 + 1, sizeof(CrashState) - 8) != 0; } // ignore f0, it just changes all the time..


// SC2 antidebug facilities have a delayed crash mechanism: if some tampering is detected, instead of crashing immediately, it sets some globals instead (including crash time, set to current time + random delay)
// every tick, it checks these globals and crashes if current time is larger than crash time
// crash state is encrypted (with key changing on every access) and protected by a spinlock
// blizzard devs care about reversers, so they've helpfully added a 'reason' field to the delayed crash state
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
		DebugVEH::instance().setWriteBreakpoint(mAddress + 7, [this](void* spinlock) { // set on spinlock
			if (*reinterpret_cast<u32*>(spinlock) != 0)
				return; // just entered spinlock, wait
			auto state = getCurrentState();
			if (state.reason != mCurState.reason)
			{
				Log::msg("Starting to crash");
				Log::stack();
			}
		});
	}

private:
	DebugDelayedCrash()
	{
		App::instance().hooker().assign(0x39F07F8, mAddress);
	}

	CrashState getCurrentState()
	{
		CrashState res = {};
		auto outPtr = &res.f0;
		u64 h1 = 0x96478FAEECCF46AE, h2 = mAddress[6];
		App::instance().decodeAntidebug(h1, h2);
		for (int i = 0; i < 6; ++i)
		{
			outPtr[i] = mAddress[i] ^ (std::rotr(h1, 11) - h2);
			h1 = std::rotr(mAddress[i], 11) - h2;
		}
		return res;
	}

	// always returns false - used as a tick function
	bool updateLastState()
	{
		auto frameIndex = mNextFrameId++;
		auto prev = mCurState;
		mCurState = getCurrentState();
		if (mCurState != prev)
		{
			Log::msg("Delayed crash state changed at frame {}: at {} (in {} ms), reason={}, fields={:016X} {:016X} {:08X} {:016X} {:016X}", frameIndex,
				mCurState.crashTick, (int)(mCurState.crashTick - GetTickCount()), mCurState.reason, mCurState.f0, mCurState.f10, mCurState.f18, mCurState.f20, mCurState.f28);
		}
		return false;
	}

private:
	u64* mAddress = nullptr;
	int mNextFrameId = 0;
	CrashState mCurState = {};
};
