module;

#include <common/win_headers.h>

export module injected.game.slowmode;

import std;
import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.cs.timingdata;

// this mirrors default implementation in game
int speedForSetting(int setting)
{
	switch (setting)
	{
	case 0: return 0x999;
	case 1: return 0xCCC;
	case 2: return 0x1000;
	case 3: return 0x1333;
	case 4: return 0x1666;
	default: return 0x1000;
	}
}

struct Timing
{
	// vfuncs
	virtual void vf0() = 0;
	virtual void vf1() = 0;
	virtual void vf2() = 0;
	virtual void vf3() = 0;
	virtual void vf4() = 0;
	virtual void vf5() = 0;
	virtual void vf6() = 0;
	virtual void vf7() = 0;
	virtual void vf8() = 0;
	virtual void vf9() = 0;
	virtual void vf10() = 0;
	virtual void vf11() = 0;
	virtual void vf12() = 0;
	virtual void vf13() = 0;
	virtual void vf14() = 0;
	virtual bool allowImmediateSpeedChange() = 0;
	virtual void vf16() = 0;
	virtual void vf17() = 0;
	virtual void vf18() = 0;
	virtual void vf19() = 0;
	virtual void vf20() = 0;
	virtual void vf21() = 0;
	virtual void vf22() = 0;
	virtual void vf23() = 0;
	virtual void vf24() = 0;
	virtual void vf25() = 0;
	virtual void vf26() = 0;
	virtual void vf27() = 0;
	virtual void vf28() = 0;
	virtual void vf29() = 0;
	virtual void vf30() = 0;
	virtual void vf31() = 0;
	virtual void vf32() = 0;
	virtual void vf33() = 0;
	virtual void vf34() = 0;
	virtual void vf35() = 0;
	virtual void vf36() = 0;
	virtual void vf37() = 0;
	virtual void setSpeedIndex(int index, bool checkIfAllowed) = 0;
	virtual void setSpeed(int speed, bool checkIfAllowed) = 0;

	inline int& minSpeedSetting() { return field<int>(0x88); }
	inline int& speedIndex() { return field<int>(0x13698); }
	inline int& speedActual() { return field<int>(0x1369C); }
	inline int& speedDesired() { return field<int>(0x136A0); }
	inline int& invSpeedActual() { return field<int>(0x136A4); }
	inline int& speedMultIdentity() { return field<int>(0x136A8); }
	inline int& speedLock() { return field<int>(0x1374C); }
	inline int& u_relToSpeed() { return field<int>(0x13768); }

private:
	template<typename T> T& field(u64 offset) { return *(T*)((char*)this + offset); }
};

export class GameSlowmode
{
public:
	static GameSlowmode& instance()
	{
		static GameSlowmode inst;
		return inst;
	}

	void install()
	{
		auto& app = App::instance();
		app.hooker().assign(0x5694230, pTiming); // timing structure is in .data segment
		//hooker.hook(0x1557580, 0, inst.replGetSpeedForSetting1); // doing this fucks up mission timer for some reason
		oriGetSpeedForSetting2 = app.hooker().hook(0x15575E0, 0xE, hookGetSpeedForSetting2);

		app.addKeybind({ VK_CAPITAL }, [this]() { toggle(1024); }); // caps lock
		//app.addKeybind({ VK_SPACE }, [this]() { toggle(256); });

		log();
	}

private:
	void toggle(int speed)
	{
		mForcedSpeed = mForcedSpeed == speed ? 0 : speed;
		Log::msg("Changing forced speed to {}", mForcedSpeed);
		auto actualSpeed = mForcedSpeed ? mForcedSpeed : speedForSetting(pTiming->speedIndex());
		TimingData::setGameSpeed(actualSpeed);
		pTiming->setSpeed(actualSpeed, false);
	}

	void log()
	{
		Log::msg("Timing: speed={}/{} (#{}), inv={} (identity={}), lock={}, changeable={}, min={}",
			pTiming->speedDesired(), pTiming->speedActual(), pTiming->speedIndex(), pTiming->invSpeedActual(),
			pTiming->speedMultIdentity(), pTiming->speedLock(), pTiming->u_relToSpeed(), pTiming->minSpeedSetting());
	}

private:
	// game interop
	Timing* pTiming = nullptr;

	// this is awkward to hook
	//static int* replGetSpeedForSetting1(int* out, int setting)
	//{
	//	auto& inst = instance();
	//	*out = inst.ForcedSpeed ? inst.ForcedSpeed : speedForSetting(setting);
	//	return out;
	//}

	int* (*oriGetSpeedForSetting2)(int*, int) = nullptr;
	static int* hookGetSpeedForSetting2(int* out, int setting)
	{
		auto& inst = instance();
		if (inst.mForcedSpeed)
		{
			*out = inst.mForcedSpeed;
			return out;
		}
		else
		{
			return inst.oriGetSpeedForSetting2(out, setting);
		}
	}

private:
	// tweak state
	int mForcedSpeed = 0;
};

//export void installRTWP(Hooker& hooker)
//{
//	auto timingVtbl = *(void***)gTiming;
//	Log::msg("SetSpeed ptr: {} {}", *(void**)gTiming, timingVtbl[39]);
//	oriTimingSetSpeed = (decltype(oriTimingSetSpeed))timingVtbl[39];
//	timingVtbl[39] = hookTimingSetSpeed;
//
//	pfnTimingDataSetSpeed(8192);
//	gTiming->setSpeed(8192, false);
//	//overrideSpeed(imagebase + 0x1557580, 8192); // this instantly affects timer above minimap, but not realtime/game timers...
//	overrideSpeed(imagebase + (0x7FF6AFA275E0 - segbase), 8192); // - this affect everything (including vfx etc), but applies only when game speed changes
//
//	 hook setGlobalTimeScale - copy entire function (up to retn) to preamble
//	oriSetGlobalTimeScale = hookAlloc.hook<decltype(oriSetGlobalTimeScale)>(imagebase + (0x7FF6AEB54280 - segbase), 0x2B, hookSetGlobalTimeScale);
//	oriSetGlobalTimeScale(32); // 16 is real min, 8 is unreliable
//
//	 stop game tick increment - this affects timers and VFX, but not game sim (unit movement, build progress, etc)
//	char* gameTickIncrement = curbase + (0x7FF6AEB4E3F3 - segbase);
//	memset(gameTickIncrement, 0x90, 7);
//}

//void overrideSpeed(char* address, u32 value)
//{
//	unsigned char buffer[] = { 0x48, 0x89, 0xC8, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC3 };
//	*(u32*)(buffer + 5) = value;
//	std::memcpy(address, buffer, sizeof(buffer));
//}

//void (*oriTimingSetSpeed)(Timing*, int, bool) = nullptr;
//void hookTimingSetSpeed(Timing* self, int speed, bool checkIfAllowed)
//{
//	Log::msg("hey ho: {:X} {}", speed, checkIfAllowed);
//	Logger::stack();
//	oriTimingSetSpeed(self, speed, checkIfAllowed);
//}

//void (*oriSetGlobalTimeScale)(int) = nullptr;
//void hookSetGlobalTimeScale(int scale)
//{
//	Log::msg("SetGlobalTimeScale: {:X}", scale);
//	Logger::stack();
//	oriSetGlobalTimeScale(scale);
//}
