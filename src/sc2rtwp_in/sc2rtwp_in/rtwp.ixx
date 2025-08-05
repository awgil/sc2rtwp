module;

#include <common/win_headers.h>

export module injected.rtwp;

import std;
import common;
import injected.logger;
import injected.hooker;

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
Timing* gTiming = nullptr;

void (*pfnTimingDataSetSpeed)(int speed) = nullptr;

int gForcedSpeed = 0;

// this is awkward to hook
int* replGetSpeedForSetting1(int* out, int setting)
{
	*out = gForcedSpeed ? gForcedSpeed : speedForSetting(setting);
	return out;
}

int* (*oriGetSpeedForSetting2)(int*, int) = nullptr;
int* hookGetSpeedForSetting2(int* out, int setting)
{
	if (gForcedSpeed)
	{
		*out = gForcedSpeed;
		return out;
	}
	else
	{
		return oriGetSpeedForSetting2(out, setting);
	}
}

void toggleRTWP(int speed)
{
	gForcedSpeed = gForcedSpeed == speed ? 0 : speed;
	Logger::log("Changing forced speed to {}", gForcedSpeed);
	auto actualSpeed = gForcedSpeed ? gForcedSpeed : speedForSetting(gTiming->speedIndex());
	pfnTimingDataSetSpeed(actualSpeed);
	gTiming->setSpeed(actualSpeed, false);
}

std::bitset<3> gCurModifiers;
void processKeyEvent(u32 vk, bool down)
{
	switch (vk)
	{
	case VK_SHIFT:
	case VK_LSHIFT:
	case VK_RSHIFT:
		gCurModifiers.set(0, down);
		break;
	case VK_CONTROL:
	case VK_LCONTROL:
	case VK_RCONTROL:
		gCurModifiers.set(1, down);
		break;
	case VK_MENU:
	case VK_LMENU:
	case VK_RMENU:
		gCurModifiers.set(2, down);
		break;
	case VK_CAPITAL: // caps lock
		if (down && gCurModifiers.none())
			toggleRTWP(1024);
		break;
	case VK_SPACE:
		if (down && gCurModifiers.none())
			toggleRTWP(256);
		break;
	}
}

LRESULT (*oriWndproc)(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) = nullptr;
LRESULT hookWndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	switch (msg)
	{
	case WM_KEYDOWN:
		if ((lparam >> 30) == 0) // bit 30 == 1 means that key was already held
			processKeyEvent(wparam, true);
		break;
	case WM_KEYUP:
		processKeyEvent(wparam, false);
		break;
	}
	return oriWndproc(hwnd, msg, wparam, lparam);
}

export void installRTWP(Hooker& hooker, char* imagebase)
{
	gTiming = reinterpret_cast<Timing*>(imagebase + 0x5694230); // timing structure is in .data segment
	pfnTimingDataSetSpeed = reinterpret_cast<decltype(pfnTimingDataSetSpeed)>(imagebase + 0x6841C0);
	//hooker.hook(imagebase + 0x1557580, 0, replGetSpeedForSetting1); // doing this fucks up mission timer for some reason
	oriGetSpeedForSetting2 = hooker.hook(imagebase + 0x15575E0, 0xE, hookGetSpeedForSetting2);
	oriWndproc = hooker.hook(imagebase + 0x24CAF0, 0xF, hookWndproc);

	Logger::log("Timing: speed={}/{} (#{}), inv={} (identity={}), lock={}, changeable={}, min={}", gTiming->speedDesired(), gTiming->speedActual(), gTiming->speedIndex(), gTiming->invSpeedActual(), gTiming->speedMultIdentity(), gTiming->speedLock(), gTiming->u_relToSpeed(), gTiming->minSpeedSetting());

	//auto timingVtbl = *(void***)gTiming;
	//Logger::log("SetSpeed ptr: {} {}", *(void**)gTiming, timingVtbl[39]);
	//oriTimingSetSpeed = (decltype(oriTimingSetSpeed))timingVtbl[39];
	//timingVtbl[39] = hookTimingSetSpeed;

	//pfnTimingDataSetSpeed(8192);
	//gTiming->setSpeed(8192, false);
	////overrideSpeed(imagebase + 0x1557580, 8192); // this instantly affects timer above minimap, but not realtime/game timers...
	//overrideSpeed(imagebase + (0x7FF6AFA275E0 - segbase), 8192); // - this affect everything (including vfx etc), but applies only when game speed changes

	// hook setGlobalTimeScale - copy entire function (up to retn) to preamble
	//oriSetGlobalTimeScale = hookAlloc.hook<decltype(oriSetGlobalTimeScale)>(imagebase + (0x7FF6AEB54280 - segbase), 0x2B, hookSetGlobalTimeScale);
	//oriSetGlobalTimeScale(32); // 16 is real min, 8 is unreliable

	// stop game tick increment - this affects timers and VFX, but not game sim (unit movement, build progress, etc)
	//char* gameTickIncrement = curbase + (0x7FF6AEB4E3F3 - segbase);
	//memset(gameTickIncrement, 0x90, 7);
}

//void overrideSpeed(char* address, u32 value)
//{
//	unsigned char buffer[] = { 0x48, 0x89, 0xC8, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC3 };
//	*(u32*)(buffer + 5) = value;
//	std::memcpy(address, buffer, sizeof(buffer));
//}

//void (*oriTimingSetSpeed)(Timing*, int, bool) = nullptr;
//void hookTimingSetSpeed(Timing* self, int speed, bool checkIfAllowed)
//{
//	Logger::log("hey ho: {:X} {}", speed, checkIfAllowed);
//	Logger::stack();
//	oriTimingSetSpeed(self, speed, checkIfAllowed);
//}

//void (*oriSetGlobalTimeScale)(int) = nullptr;
//void hookSetGlobalTimeScale(int scale)
//{
//	Logger::log("SetGlobalTimeScale: {:X}", scale);
//	Logger::stack();
//	oriSetGlobalTimeScale(scale);
//}
