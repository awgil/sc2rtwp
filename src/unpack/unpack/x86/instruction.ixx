module;

#include <capstone/capstone.h>
#define RFL_ENUM_RANGE_MAX X86_INS_ENDING
#include <rfl.hpp>

export module unpack.x86.instruction;

export import unpack.x86.operand;

namespace x86 {

export struct Mnem
{
	using Value = x86_insn;
	static constexpr int Count = X86_INS_ENDING;

	// per-instruction metadata
	struct Info
	{
		std::string name;
		bool isConditionalJump = false;
	};

	Mnem(Value v = {}) : mValue(v) {}
	operator Value() const { return mValue; }

	auto& info() const { return mMeta[mValue]; }
	auto& name() const { return info().name; }
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
	std::array<Operand, 4> ops;

	auto operands(this auto&& self) { return std::span{ self.ops.data(), self.opcount }; }
};

}

// formatters
using namespace x86;

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
