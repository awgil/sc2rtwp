module;

#include <capstone/capstone.h>
#define RFL_ENUM_RANGE_MAX X86_INS_ENDING
#include <rfl.hpp>

export module unpack.x86.instruction;

export import unpack.x86.condition;
export import unpack.x86.operand;

namespace x86 {

export enum class Prefix : u8
{
	none = 0,
	lock = 0xF0,
	repnz = 0xF2,
	repz = 0xF3,
};

export struct Mnem
{
	using Value = x86_insn;
	static constexpr int Count = X86_INS_ENDING;

	// per-instruction metadata
	struct Info
	{
		std::string name;
		ConditionTest conditionCode;
		bool isConditionalJump = false;
	};

	Mnem(Value v = {}) : mValue(v) {}
	operator Value() const { return mValue; }

	auto& info() const { return mMeta[mValue]; }
	auto& name() const { return info().name; }
	auto conditionCode() const { return info().conditionCode; }
	auto isConditionalJump() const { return info().isConditionalJump; }

private:
	Value mValue;
	static const std::array<Info, Count> mMeta;
};

const std::array<Mnem::Info, Mnem::Count> Mnem::mMeta = []() {
	std::array<Info, Count> info;

	// generate instruction names
	const std::string_view prefix = "X86_INS_";
	for (int i = 1; i < Count; ++i)
	{
		auto& name = info[i].name;
		name = rfl::enum_to_string(static_cast<Value>(i));
		ensure(name.starts_with(prefix));
		name = name.substr(prefix.length());
		std::ranges::transform(name, name.begin(), [](char c) { return std::tolower(c); });
	}

	// jcc/setcc conditions
	info[X86_INS_JO].conditionCode = info[X86_INS_SETO].conditionCode = { Condition::OF, false };
	info[X86_INS_JNO].conditionCode = info[X86_INS_SETNO].conditionCode = { Condition::OF, true };
	info[X86_INS_JB].conditionCode = info[X86_INS_SETB].conditionCode = { Condition::CF, false };
	info[X86_INS_JAE].conditionCode = info[X86_INS_SETAE].conditionCode = { Condition::CF, true };
	info[X86_INS_JE].conditionCode = info[X86_INS_SETE].conditionCode = { Condition::ZF, false };
	info[X86_INS_JNE].conditionCode = info[X86_INS_SETNE].conditionCode = { Condition::ZF, true };
	info[X86_INS_JBE].conditionCode = info[X86_INS_SETBE].conditionCode = { Condition::CZ, false };
	info[X86_INS_JA].conditionCode = info[X86_INS_SETA].conditionCode = { Condition::CZ, true };
	info[X86_INS_JS].conditionCode = info[X86_INS_SETS].conditionCode = { Condition::SF, false };
	info[X86_INS_JNS].conditionCode = info[X86_INS_SETNS].conditionCode = { Condition::SF, true };
	info[X86_INS_JP].conditionCode = info[X86_INS_SETP].conditionCode = { Condition::PF, false };
	info[X86_INS_JNP].conditionCode = info[X86_INS_SETNP].conditionCode = { Condition::PF, true };
	info[X86_INS_JL].conditionCode = info[X86_INS_SETL].conditionCode = { Condition::SO, false };
	info[X86_INS_JGE].conditionCode = info[X86_INS_SETGE].conditionCode = { Condition::SO, true };
	info[X86_INS_JLE].conditionCode = info[X86_INS_SETLE].conditionCode = { Condition::LE, false };
	info[X86_INS_JG].conditionCode = info[X86_INS_SETG].conditionCode = { Condition::LE, true };

	// conditional jumps
	for (auto ins : { X86_INS_JO, X86_INS_JNO, X86_INS_JB, X86_INS_JAE, X86_INS_JE, X86_INS_JNE, X86_INS_JBE, X86_INS_JA,
		X86_INS_JS, X86_INS_JNS, X86_INS_JP, X86_INS_JNP, X86_INS_JL, X86_INS_JGE, X86_INS_JLE, X86_INS_JG,
		X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ, X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE })
	{
		info[ins].isConditionalJump = true;
	}

	return info;
}();

export struct Instruction
{
	i32 rva;
	Mnem mnem;
	u8 length;
	u8 opcount;
	Prefix prefix; // group 1 (lock/repeat) only
	std::array<Operand, 4> ops;

	i32 endRVA() const { return rva + length; }
	auto operands(this auto&& self) { return std::span{ self.ops.data(), self.opcount }; }
};

}

// formatters
using namespace x86;

export template<> struct std::formatter<Prefix>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
	auto format(const Prefix& obj, format_context& ctx) const { return ranges::copy(rfl::enum_to_string(obj), ctx.out()).out; }
};

export template<> struct std::formatter<Mnem>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
	auto format(const Mnem& obj, format_context& ctx) const { return ranges::copy(obj.name(), ctx.out()).out; }
};

export template<> struct std::formatter<Instruction>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

	auto format(const Instruction& obj, format_context& ctx) const
	{
		if (obj.prefix != Prefix::none)
			format_to(ctx.out(), "{} ", obj.prefix);
		format_to(ctx.out(), "{}", obj.mnem);
		for (int i = 0; auto& op : obj.operands())
		{
			if (i++)
				*ctx.out()++ = ',';
			format_to(ctx.out(), " {}", op);
		}
		return ctx.out();
	}
};
