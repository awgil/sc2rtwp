export module injected.cs.unit;

import std;
import common;
import injected.logger;
import injected.app;

export struct Unit
{
	u32 id; // low 18 bits are version, remaining 14 bits are index (4 low bits are offset within page, 10 high are page index)
	char unk1[0x70]; // 0x1C/0x20: encoded x/y
	i32 curSpeedX; // fixed point (<<12)
	i32 curSpeedY; // fixed point
	char unk2[0x1E4];
};
static_assert(sizeof(Unit) == 0x260);

export struct UnitManager
{
	u32 f0; // maybe num active?..
	u32 maxIndex;
	// 13 qwords, all seem to be equal to encoded zero?..
	// array of 1024 encoded pointers to pages of 16 units
};

export class UnitLookup
{
public:
	static UnitLookup& instance()
	{
		static UnitLookup inst;
		return inst;
	}

	UnitManager* manager() const { return mManager; }

	Unit* findUnit(u32 index) const
	{
		return mFindUnit(mManager, index);
	}

	void cancelMovementInterpolation(Unit* unit)
	{
		mUnitStopInterpolation(unit);
	}

	void dump() const
	{
		Log::msg("Unit dump: {}/{}", mManager->f0, mManager->maxIndex);
		for (u32 i = 0; i < mManager->maxIndex; ++i)
		{
			auto unit = findUnit(i);
			Log::msg("[{}] = {}v{} ({:X}x{:X})", i, unit->id >> 18, unit->id & 0x3FFFF, unit->curSpeedX, unit->curSpeedY);
		}
	}

private:
	UnitLookup()
	{
		auto& hooker = App::instance().hooker();
		hooker.assign(0x3B80B40, mManager);
		hooker.assign(0x6603D0, mFindUnit);
		hooker.assign(0x861210, mUnitStopInterpolation);
	}

private:
	UnitManager* mManager;
	Unit* (*mFindUnit)(UnitManager*, u32) = nullptr;
	void (*mUnitStopInterpolation)(Unit*) = nullptr;
};
