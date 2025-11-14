export module unpack.x86.operand;

export import unpack.x86.reg;

namespace x86 {

export enum class OpType : u8
{
	Invalid = 0, // not an operand
	Reg = 1,
	Imm = 2,
	Mem = 3,
};

// memory-referencing operand
// note: theoretically we need 3 bits for seg, 5 bits for base/index, 2 bits for scale and 1 bit for 32/64bit
export struct OpMem
{
	Reg seg; // none if implicit (current) segment, otherwise segment override
	Reg base; // none, rip, imagebase, or 32/64bit gpr
	Reg index; // none or 32/64bit gpr
	i8 scale; // 1/2/4/8 if there is index, or undefined otherwise (eg can be 0 or 1)
	i32 displacement;

	bool operator==(const OpMem&) const = default;
};
static_assert(sizeof OpMem == 8);

// TODO: there's quite a bit of wasted space here unfortunately...
export struct Operand
{
	OpType type;
	i8 size;
	// TODO: access?..
	union
	{
		Reg reg;
		i64 imm;
		OpMem mem;
	};

	Operand() : type(OpType::Invalid), size(0), imm(0) {}
	explicit Operand(Reg reg) : type(OpType::Reg), size(reg.width()), reg(reg) {}
	explicit Operand(Reg reg, i8 size) : type(OpType::Reg), size(size), reg(reg) {}
	explicit Operand(Reg::Value reg, i8 size) : type(OpType::Reg), size(size), reg(reg) {}
	explicit Operand(i64 imm, i8 size) : type(OpType::Imm), size(size), imm(imm) {}
	explicit Operand(OpMem mem, i8 size) : type(OpType::Mem), size(size), mem(mem) {}

	template<std::integral T> T immediate() const { ensure(type == OpType::Imm); return static_cast<T>(imm); }

	bool operator==(const Operand& rhs) const
	{
		if (type != rhs.type || size != rhs.size)
			return false;
		switch (type)
		{
		case OpType::Reg: return reg == rhs.reg;
		case OpType::Imm: return imm == rhs.imm;
		case OpType::Mem: return mem == rhs.mem;
		default: return true;
		}
	}

	bool operator==(Reg rhs) const { return type == OpType::Reg && reg == rhs; }
	bool operator==(Reg::Value rhs) const { return type == OpType::Reg && reg == rhs; }
	bool operator==(i64 rhs) const { return type == OpType::Imm && (size < 8 ? (((imm ^ rhs) & ((1ull << 8 * size) - 1)) == 0) : imm == rhs); }
	bool operator==(const OpMem& rhs) const { return type == OpType::Mem && mem == rhs; }
};
static_assert(sizeof Operand == 16);

}

// formatters
using namespace x86;

export template<> struct std::formatter<OpMem>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

	auto format(const OpMem& obj, format_context& ctx) const
	{
		if (obj.seg)
			format_to(ctx.out(), "{}:", obj.seg);
		*ctx.out()++ = '[';

		auto formatIndex = [&](bool plus) {
			if (!obj.index)
				return;
			if (plus)
				ranges::copy(" + ", ctx.out());
			if (obj.scale > 1)
				format_to(ctx.out(), "{} * {}", obj.scale, obj.index);
			else
				format_to(ctx.out(), "{}", obj.index);
		};
		auto formatOffset = [&]() {
			if (obj.displacement > 0)
				format_to(ctx.out(), " + 0x{:X}", obj.displacement);
			else if (obj.displacement < 0)
				format_to(ctx.out(), " - 0x{:X}", -obj.displacement);
		};

		if (!obj.base)
		{
			if (!obj.index)
			{
				format_to(ctx.out(), "0x{:X}", static_cast<u32>(obj.displacement));
			}
			else
			{
				formatIndex(false);
				formatOffset();
			}
		}
		else if (obj.base == Reg::imagebase)
		{
			format_to(ctx.out(), "rva 0x{:X}", static_cast<u32>(obj.displacement));
			formatIndex(true);
		}
		else
		{
			format_to(ctx.out(), "{}", obj.base);
			formatIndex(true);
			formatOffset();
		}

		*ctx.out()++ = ']';
		return ctx.out();
	}
};

export template<> struct std::formatter<Operand>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

	auto formatSize(u8 size, format_context& ctx) const
	{
		switch (size)
		{
		case 1: return format_to(ctx.out(), "byte");
		case 2: return format_to(ctx.out(), "word");
		case 4: return format_to(ctx.out(), "dword");
		case 8: return format_to(ctx.out(), "qword");
		case 16: return format_to(ctx.out(), "xmmword");
		case 32: return format_to(ctx.out(), "ymmword");
		case 64: return format_to(ctx.out(), "zmmword");
		default: return format_to(ctx.out(), "{}", size);
		}
	}

	// TODO: signedness is ass here... probably should allow user to specify
	auto formatImm(const Operand& obj, format_context& ctx) const
	{
		switch (obj.size)
		{
		case 1: return format_to(ctx.out(), "0x{:X}", static_cast<u8>(obj.imm));
		case 2: return format_to(ctx.out(), "0x{:X}", static_cast<u16>(obj.imm));
		case 4: return format_to(ctx.out(), "0x{:X}", static_cast<u32>(obj.imm));
		default: return format_to(ctx.out(), "0x{:X}", static_cast<u64>(obj.imm));
		}
	}

	auto format(const Operand& obj, format_context& ctx) const
	{
		switch (obj.type)
		{
		case OpType::Reg: return format_to(ctx.out(), "{}", obj.reg.name());
		case OpType::Imm: return formatImm(obj, ctx);
		case OpType::Mem: return format_to(formatSize(obj.size, ctx), " ptr {}", obj.mem);
		default: return format_to(ctx.out(), "???");
		}
	}
};
