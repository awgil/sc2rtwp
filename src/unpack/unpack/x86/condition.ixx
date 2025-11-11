export module unpack.x86.condition;

export import std;
export import common;

namespace x86 {

// Conditions used by jcc/setcc instructions
// Each condition checkes either single flag value, or some combination ('pseudo-flag')
// Order matches condition test field encoding, see B.1.4.7 in intel's manual - this can allow extracting bits 1-3 of the instruction byte...
export enum class Condition : u8
{
	OF = 0, // jo - jno
	CF = 1, // jc/jb/jnae - jnc/jnb/jae
	ZF = 2, // je/jz - jne/jnz
	CZ = 3, // jbe/jna - jnbe/ja (CF | ZF)
	SF = 4, // js - jns
	PF = 5, // jp/jpe - jnp/jpo
	SO = 6, // jl/jnge - jnl/jge (SF ^ OF)
	LE = 7, // jle/jng - jnle/jg (ZF | (SF ^ OF))
};

// Condition test value combines condition (bits 1-3) and negation (bit 0)
// Bit 4 is always set to 1 for valid test value, which allows representing non-value as 0
export class ConditionTest
{
public:
	static constexpr u8 ValidBit = 0x10;

	ConditionTest() : mValue(0) {} // default constructor creates invalid value
	ConditionTest(Condition cond, bool negated) : mValue(ValidBit | std::to_underlying(cond) << 1 | (negated ? 1 : 0)) {}

	operator bool() const { return mValue != 0; }
	Condition condition() const { return static_cast<Condition>(mValue >> 1 & 7); }
	bool negated() const { return mValue & 1; }

private:
	u8 mValue{};
};
static_assert(sizeof ConditionTest == 1);

// a set of known values for condition flags
// TODO: does this belong to analysis?..
export class ConditionState
{
public:
	static u8 mask(Condition c) { return 1 << std::to_underlying(c); }

	void setAll(u8 known, u8 values)
	{
		ensure((values & ~known) == 0);
		mKnown = known;
		mValue = values;
	}

	bool isKnown(Condition flag) const { return (mKnown & mask(flag)) != 0; }
	bool isSet(Condition flag) const { return (mValue & mask(flag)) != 0; }

	void forget(Condition flag)
	{
		auto m = mask(flag);
		mKnown &= ~m;
		mValue &= ~m;
	}

	void setConditional(Condition flag, bool value)
	{
		// TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
		setRaw(flag, value);
	}

	void setFlag(Condition flag, bool value)
	{
		setRaw(flag, value);
		if (flag == Condition::CF || flag == Condition::ZF)
			updateOrPseudoflag(Condition::CZ, Condition::CF, Condition::ZF);
		if (flag == Condition::OF || flag == Condition::SF)
			updateXorPseudoflag(Condition::SO, Condition::OF, Condition::SF);
		if (flag == Condition::OF || flag == Condition::SF || flag == Condition::ZF)
			updateXorPseudoflag(Condition::LE, Condition::ZF, Condition::SO);
	}

private:
	void setRaw(Condition flag, bool value)
	{
		auto m = mask(flag);
		mKnown |= m;
		if (value)
			mValue |= m;
		else
			mValue &= ~m;
	}

	void updateXorPseudoflag(Condition flag, Condition f1, Condition f2)
	{
		if (isKnown(f1) && isKnown(f2))
			setRaw(flag, isSet(f1) != isSet(f2));
		else
			forget(flag);
	}

	void updateOrPseudoflag(Condition flag, Condition f1, Condition f2)
	{
		if (isSet(f1) || isSet(f2)) // set implies known
			setRaw(flag, true);
		else if (isKnown(f1) && isKnown(f2))
			setRaw(flag, false);
		else
			forget(flag);
	}

private:
	u8 mKnown = 0;
	u8 mValue = 0; // invariant: mValue & ~mKnown == 0 (ie all unknown bits are zero)
};

}
