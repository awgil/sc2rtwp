export module injected.cs.timingdata;

import common;
import injected.app;

// the structure is allocated on heap, and the pointer is xorred with some constants
// to get the pointer, we exploit the fact that static function setGlobalTimeScale is very trivial and happens to keep unobfuscated pointer in rax on return
export struct TimingData
{
	static TimingData* instance()
	{
		auto& hooker = App::instance().hooker();
		auto getGlobalTimeScale = hooker.get<int*(int*)>(0x682320);
		auto setGlobalTimeScale = hooker.get<TimingData*(int)>(0x684280);
		int scale = 0;
		getGlobalTimeScale(&scale);
		return setGlobalTimeScale(scale);
	}

	static void setGameSpeed(int speed)
	{
		static auto pfn = App::instance().hooker().get<void(int)>(0x6841C0);
		pfn(speed);
	}

	// 00000001 = time of day paused
	// 00000800 = mission time paused
	u32& flags() { return field<u32>(0x4); }

	u32& gameTime() { return field<u32>(0x64); }
	u32& missionTime() { return field<u32>(0x68); }
	u32& realTime() { return field<u32>(0x78); }
	u32& gameSpeed() { return field<u32>(0x7C); }
	u32& realTicksPer256GameTicks() { return field<u32>(0x80); } // == 2^20 / speed
	u32& speedIndex() { return field<u32>(0x84); }
	u32& minSpeedIndex() { return field<u32>(0x88); }
	u32& globalTimeScale() { return field<u32>(0xA0); }

private:
	template<typename T> T& field(u64 offset) { return *reinterpret_cast<T*>(reinterpret_cast<char*>(this) + offset); }
};
