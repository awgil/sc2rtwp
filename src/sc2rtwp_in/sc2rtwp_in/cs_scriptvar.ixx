export module injected.cs.scriptvar;

import std;
import common;
import injected.logger;
import injected.app;

export struct VariableIdentifier
{
	u16 index;
	u16 version;
};

export enum class ScriptVariableType : u8
{
	Point = 14,
	Timer = 20,
	UnitGroup = 23,
};

export enum class TimerType : u32
{
	Game = 0,
	Real = 1,
	AI = 2,
};

export struct ScriptVariable
{
	void** vtable;
	VariableIdentifier ident;
	u32 fC; // padding?
};

export struct ScriptVariableTimer : ScriptVariable
{
	bool autoReset;
	bool isPaused;
	bool isExpired;
	u8 pad13;
	TimerType timerType;
	int elapsedTicks; // num ticks timer has been running
	int limitTicks; // when reaching this, timer expires
	int lastTick; // tick count for corresponding timer on last update
	int pad24;
};

export struct ScriptVariableRef
{
	u16 version;
	u16 f2;
	u16 f4;
	ScriptVariableType type;
	u8 f7; // padding?
	ScriptVariable* impl;
};

export class ScriptVariables
{
public:
	static ScriptVariables& instance()
	{
		static ScriptVariables inst;
		return inst;
	}

	std::span<VariableIdentifier> activeTimers() const { return { *mActiveTimers, *mNumActiveTimers }; }
	const ScriptVariableRef& scriptVar(u16 index) const { return (*mScriptVariables)[index]; }

private:
	ScriptVariables()
	{
		auto& hooker = App::instance().hooker();

		auto tickActiveTimersRVA = 0xA30AA0;
		hooker.assignRipRelative(tickActiveTimersRVA + 0x23, mNumActiveTimers);
		hooker.assignRipRelative(tickActiveTimersRVA + 0x30, mActiveTimers);
		hooker.assignRipRelative(tickActiveTimersRVA + 0x41, mScriptVariables);
		//hooker.assignRipRelative(tickActiveTimersRVA + 0x63, mGetTimerTick);

		Log::msg("Num active timers: {}", *mNumActiveTimers);
	}

private:
	u32* mNumActiveTimers = nullptr;
	VariableIdentifier** mActiveTimers = nullptr;
	ScriptVariableRef** mScriptVariables = nullptr; // 65536 entries
	//int* (*mGetTimerTick)(int* outTick, int type) = nullptr;
};
