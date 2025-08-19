module;

#include <common/win_headers.h>

export module injected.game.rtwp;

import std;
import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.cs.timingdata;
import injected.cs.scriptvar;
import injected.cs.unit;

struct MissileAnim
{
	float startT;
	i32 field_4;
	i32 endIndex;
	i32 field_C;
	i32 numLimits;
	float limits[2];
	char field_1C[20];
	i32 finalPosIdx;
	char field_34[12];
	float positions[3 * 2];
	char field_58[128];
	i32 finalRotIdx;
	float endT;
	i32 field_E0;
	i32 field_E4;
	float rotations[4 * 2];
};
static_assert(sizeof MissileAnim == 0x108);

// SC2 deals with timing in a somewhat weird way:
// - every frame, it converts real time into game time (scaled by game speed), accumulates it, and whenever it reaches a threshold, executes simulation tick
// - simulation tick increments 'game' timer unconditionally by fixed value 256, increments 'real' timer by inversely scaled value, and executes various logic ticks (triggers, unit movement, etc)
// - if we completely skip simulation tick, that breaks vfx/animations - they rely on 'game' timer being incremented (a consequence is that vfx/anim playback speed depends on game speed, which is weird)
// - if we increment 'game' time normally and skip everything else, things work well - except that game timers catch up immediately on unpause (since they use 'game' time to calculate their progress)
// So the solution is to hook simulation tick, when paused increment only 'game' time (and skip everything else), then also manually fix up all timers.
// TODO: consider instead decoupling anim timers somehow? there's an annoying bug currently, when paused we constantly interpolate positions/rotations of all units between last two values
export class GameRTWP
{
public:
	static GameRTWP& instance()
	{
		static GameRTWP inst;
		return inst;
	}

	void install()
	{
		auto& app = App::instance();
		oriTickSimulation = app.hooker().hook(0x67BCE0, 0xF, hookTickSimulation);

		// do not tick missiles while game is paused
		oriMissileTick = app.hooker().hook(0x1F372B0, 0x12, hookMissileTick);

		// do not crash the game on unpause if missile interpolation is slightly wrong
		// the interpolation code will set lookup index to UINT32_MAX on failure and do out-of-bounds access, just extrapolate a bit instead...
		auto rvaMissileAnimGetInterpolatedPosRot = 0x1F33C80;
		memset(app.hooker().imagebase() + rvaMissileAnimGetInterpolatedPosRot + 0xCA, 0x90, 3); // nop out 'or ecx, 0xFFFFFFFF'
		// TODO: remove hook, it's just logging
		//oriMissileAnimGetInterpolatedPosRot = app.hooker().hook(rvaMissileAnimGetInterpolatedPosRot, 0x12, hookMissileAnimGetInterpolatedPosRot);

		app.addKeybind({ VK_SPACE }, [this]() { toggle(); });

		// alternative: in-place patching, just replace antitamper checks with our stuff
		//auto segbase = 0x7FF6AE4D0000;
		//auto patchStartRVA = 0x7FF6AEB4BE00 - segbase;
		//auto normalStartRVA = 0x7FF6AEB4E3C3 - segbase;
		////auto skipRVA = 0x7FF6AEB4E3FA - segbase; // skip nothing, just test code movement...
		//auto skipRVA = 0x7FF6AEB4E6AB - segbase; // skip everything
		////auto skipRVA = 0x7FF6AEB4E552 - segbase;
		//static_assert(FIELD_OFFSET(GameRTWP, mPaused) == 8);
		//unsigned char code[] = {
		//	/* 0x00 */ 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, const
		//	/* 0x0A */ 0x8A, 0x52, 0x08, // mov dl, [rdx + this::mPaused]
		//	/* 0x0D */ 0x84, 0xD2, // test dl, dl
		//	/* 0x0F */ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // jz ...
		//	/* 0x15 */ //0xE9, 0x00, 0x00, 0x00, 0x00, // jmp ...
		//};
		//auto copyLen = 0x37;
		//*(void**)(code + 0x02) = this;
		//*(u32*)(code + 0x11) = normalStartRVA - patchStartRVA - 0x15;
		////*(u32*)(code + 0x16) = skipRVA - patchStartRVA - 0x1A;
		//memcpy(app.imagebase() + patchStartRVA, code, sizeof(code));

		//memcpy(app.imagebase() + patchStartRVA + sizeof(code), app.imagebase() + normalStartRVA, copyLen);
		//auto moveDelta = normalStartRVA - patchStartRVA - sizeof(code);
		//*(u32*)(app.imagebase() + patchStartRVA + sizeof(code) + 0x07) += moveDelta;
		//*(u32*)(app.imagebase() + patchStartRVA + sizeof(code) + 0x0D) += moveDelta;
		//*(u32*)(app.imagebase() + patchStartRVA + sizeof(code) + 0x19) += moveDelta;
		//*(u32*)(app.imagebase() + patchStartRVA + sizeof(code) + 0x1F) += moveDelta;

		//auto finalJmp = app.imagebase() + patchStartRVA + sizeof(code) + copyLen;
		//*finalJmp = 0xE9; // jmp
		//*(u32*)(finalJmp + 1) = skipRVA - patchStartRVA - sizeof(code) - copyLen - 5;
	}

private:
	void toggle()
	{
		auto& tick = TimingData::instance()->gameTime();
		if (mPauseAtTick)
		{
			Log::msg("Unpausing at {}", tick);
			mPauseAtTick = 0;
		}
		else
		{
			Log::msg("Pausing at {}", tick);
			mPauseAtTick = tick;

			auto& units = UnitLookup::instance();
			for (u32 i = 0; i < units.manager()->maxIndex; ++i)
			{
				auto unit = units.findUnit(i);
				if (unit && (unit->id >> 18) == i)
				{
					units.cancelMovementInterpolation(unit);
				}
			}
		}
	}

private:
	// game interop
	void (*oriTickSimulation)() = nullptr;
	static void hookTickSimulation()
	{
		auto& inst = instance();
		if (inst.mPauseAtTick)
		{
			auto& tick = TimingData::instance()->gameTime();
			tick += 0x100;

			// update last-count for all timers to simulate them being paused
			auto& sv = ScriptVariables::instance();
			for (auto ident : sv.activeTimers())
			{
				auto& ref = sv.scriptVar(ident.index);
				if (ref.type == ScriptVariableType::Timer && ref.impl)
				{
					auto* timer = static_cast<ScriptVariableTimer*>(ref.impl);
					if (!timer->isExpired && timer->timerType == TimerType::Game)
					{
						timer->lastTick += 0x100;
					}
				}
			}
		}
		else
		{
			// just call normal function
			inst.oriTickSimulation();
		}
	}

	void (*oriMissileTick)(void*) = nullptr;
	static void hookMissileTick(void* self)
	{
		auto& inst = instance();
		if (!inst.mPauseAtTick)
			inst.oriMissileTick(self);
	}

	//void (*oriMissileAnimGetInterpolatedPosRot)(MissileAnim*, float, i32*) = nullptr;
	//static void hookMissileAnimGetInterpolatedPosRot(MissileAnim* self, float t, i32* out)
	//{
	//	auto& inst = instance();
	//	auto index = self->finalPosIdx;
	//	if (t < self->endT)
	//	{
	//		index = self->endIndex;
	//		if (t < self->startT)
	//		{
	//			int limitsCount = self->numLimits;
	//			int i = 0;
	//			if (limitsCount > 2)
	//				limitsCount = 2;
	//			if (limitsCount)
	//			{
	//				while (t < self->limits[index])
	//				{
	//					index = ((unsigned char)index - 1) & 1;
	//					if (++i >= limitsCount)
	//					{
	//						index = -1;
	//						break;
	//					}
	//				}
	//			}
	//			else
	//			{
	//				index = -1;
	//			}
	//		}
	//	}
	//	Log::msg("Interp {}: {} - {}, #{}/{}, lims={}/{}, pos=[{}, {}, {}]/[{}, {}, {}], idx={}", t, self->endT, self->startT, self->endIndex, self->numLimits, self->limits[0], self->limits[1],
	//		self->positions[0], self->positions[1], self->positions[2], self->positions[3], self->positions[4], self->positions[5], index);
	//	inst.oriMissileAnimGetInterpolatedPosRot(self, t, out);
	//}

private:
	// tweak state
	u32 mPauseAtTick = 0; // 0 if not paused
};
