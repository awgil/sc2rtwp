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

}
