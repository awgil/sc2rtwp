export module unpack.x86.reg;

export import std;
export import common;

namespace x86 {

// x86 register
// not implemented (yet?): flags (e/r, fpu, etc), bnd, avx k, fpu/mmx, dr, cr
export struct Reg
{
	// enum with all supported registers
	enum Value : u8
	{
		// special & pseudo registers
		none = 0x00, // invalid, not initialized, not set, etc...
		//zero = 0x01, // pseudo-register always equal to zero
		imagebase = 0x02, // pseudo-register always equal to imagebase (used for converting RIP-relative addresses)
		rip = 0x03,
		// gaps: 0x04-0x07

		// segment registers (0000 1xxx)
		es = 0x08, cs = 0x09, ss = 0x0A, ds = 0x0B, fs = 0x0C, gs = 0x0D,
		// gaps: 0x0E-0x0F

		// 8-bit 'high' gprs (0001 00xx) - ax cx dx bx sp bp si di
		ah = 0x10, ch = 0x11, dh = 0x12, bh = 0x13,
		// gaps: 0x14-0x1F

		// 8-bit gprs (0010 xxxx)
		al = 0x20, cl = 0x21, dl = 0x22, bl = 0x23, spl = 0x24, bpl = 0x25, sil = 0x26, dil = 0x27, r8b = 0x28, r9b = 0x29, r10b = 0x2A, r11b = 0x2B, r12b = 0x2C, r13b = 0x2D, r14b = 0x2E, r15b = 0x2F,

		// 16-bit gprs (0011 xxxx)
		ax = 0x30, cx = 0x31, dx = 0x32, bx = 0x33, sp = 0x34, bp = 0x35, si = 0x36, di = 0x37, r8w = 0x38, r9w = 0x39, r10w = 0x3A, r11w = 0x3B, r12w = 0x3C, r13w = 0x3D, r14w = 0x3E, r15w = 0x3F,

		// 32-bit gprs (0100 xxxx)
		eax = 0x40, ecx = 0x41, edx = 0x42, ebx = 0x43, esp = 0x44, ebp = 0x45, esi = 0x46, edi = 0x47, r8d = 0x48, r9d = 0x49, r10d = 0x4A, r11d = 0x4B, r12d = 0x4C, r13d = 0x4D, r14d = 0x4E, r15d = 0x4F,

		// 64-bit gprs (0101 xxxx)
		rax = 0x50, rcx = 0x51, rdx = 0x52, rbx = 0x53, rsp = 0x54, rbp = 0x55, rsi = 0x56, rdi = 0x57, r8 = 0x58, r9 = 0x59, r10 = 0x5A, r11 = 0x5B, r12 = 0x5C, r13 = 0x5D, r14 = 0x5E, r15 = 0x5F,

		// gaps: 0x60-0x7F

		// xmm (100x xxxx)
		xmm0 = 0x80, xmm1 = 0x81, xmm2 = 0x82, xmm3 = 0x83, xmm4 = 0x84, xmm5 = 0x85, xmm6 = 0x86, xmm7 = 0x87, xmm8 = 0x88, xmm9 = 0x89, xmm10 = 0x8A, xmm11 = 0x8B, xmm12 = 0x8C, xmm13 = 0x8D, xmm14 = 0x8E, xmm15 = 0x8F,
		xmm16 = 0x90, xmm17 = 0x91, xmm18 = 0x92, xmm19 = 0x93, xmm20 = 0x94, xmm21 = 0x95, xmm22 = 0x96, xmm23 = 0x97, xmm24 = 0x98, xmm25 = 0x99, xmm26 = 0x9A, xmm27 = 0x9B, xmm28 = 0x9C, xmm29 = 0x9D, xmm30 = 0x9E, xmm31 = 0x9F,

		// ymm (101x xxxx)
		ymm0 = 0xA0, ymm1 = 0xA1, ymm2 = 0xA2, ymm3 = 0xA3, ymm4 = 0xA4, ymm5 = 0xA5, ymm6 = 0xA6, ymm7 = 0xA7, ymm8 = 0xA8, ymm9 = 0xA9, ymm10 = 0xAA, ymm11 = 0xAB, ymm12 = 0xAC, ymm13 = 0xAD, ymm14 = 0xAE, ymm15 = 0xAF,
		ymm16 = 0xB0, ymm17 = 0xB1, ymm18 = 0xB2, ymm19 = 0xB3, ymm20 = 0xB4, ymm21 = 0xB5, ymm22 = 0xB6, ymm23 = 0xB7, ymm24 = 0xB8, ymm25 = 0xB9, ymm26 = 0xBA, ymm27 = 0xBB, ymm28 = 0xBC, ymm29 = 0xBD, ymm30 = 0xBE, ymm31 = 0xBF,

		// ymm (110x xxxx)
		zmm0 = 0xC0, zmm1 = 0xC1, zmm2 = 0xC2, zmm3 = 0xC3, zmm4 = 0xC4, zmm5 = 0xC5, zmm6 = 0xC6, zmm7 = 0xC7, zmm8 = 0xC8, zmm9 = 0xC9, zmm10 = 0xCA, zmm11 = 0xCB, zmm12 = 0xCC, zmm13 = 0xCD, zmm14 = 0xCE, zmm15 = 0xCF,
		zmm16 = 0xD0, zmm17 = 0xD1, zmm18 = 0xD2, zmm19 = 0xD3, zmm20 = 0xD4, zmm21 = 0xD5, zmm22 = 0xD6, zmm23 = 0xD7, zmm24 = 0xD8, zmm25 = 0xD9, zmm26 = 0xDA, zmm27 = 0xDB, zmm28 = 0xDC, zmm29 = 0xDD, zmm30 = 0xDE, zmm31 = 0xDF,

		// gaps: 0xE0-0xFF
	};

	// per-register metadata
	struct Info
	{
		std::string_view name;
		int width; // in bytes
		int foffset; // offset in virtual 'register file'

		auto frange() const { return std::pair(foffset, foffset + width); }
	};

	Reg(Value v = none) : mValue(v) {}
	operator Value() const { return mValue; }

	auto& info() const { return mMeta[mValue]; }
	auto name() const { return info().name; }
	auto width() const { return info().width; }
	auto foffset() const { return info().foffset; }
	auto frange() const { return info().frange(); }

	auto isSegment() const { return mValue >= es && mValue <= gs; }
	auto segIndex() const { ensure(isSegment()); return mValue - es; }

	auto isGPR32() const { return (mValue & 0xF0) == eax; }
	auto isGPR64() const { return (mValue & 0xF0) == rax; }
	auto isGPR32Or64() const { return (mValue & 0xE0) == eax;}
	auto gprIndex() const { return mValue & 0x0F; }

	// factories to create register of specific type by index
	static Reg makeRaw(int value) { ensure(value >= 0 && value < 256); return static_cast<Value>(value); }
	static Reg makeSegment(int index) { ensure(index >= 0 && index < 6); return static_cast<Value>(0x08 | index); }
	static Reg makeGPR32(int index) { return static_cast<Value>(eax | index); }
	static Reg makeGPR64(int index) { return static_cast<Value>(rax | index); }

private:
	Value mValue{};
	static const std::array<Info, 256> mMeta;
};

const std::array<Reg::Info, 256> Reg::mMeta = []() {
	std::array<Reg::Info, 256> info;

	int pos = 0;
	auto defineSpecial = [&](Value v, std::string_view name, int width) { info[v] = Info{ name, width, pos -= width }; };
	defineSpecial(none, "none", 0);
	//defineSpecial(zero, "zero", 8);
	defineSpecial(imagebase, "imagebase", 8);
	defineSpecial(rip, "rip", 8);
	defineSpecial(es, "es", 2);
	defineSpecial(cs, "cs", 2);
	defineSpecial(ss, "ss", 2);
	defineSpecial(ds, "ds", 2);
	defineSpecial(fs, "fs", 2);
	defineSpecial(gs, "gs", 2);

	pos = 0;
	auto defineGPR = [&](int index, std::string_view qname, std::string_view dname, std::string_view wname, std::string_view bname, std::string_view hname = {}) {
		info[rax + index] = Info{ qname, 8, pos };
		info[eax + index] = Info{ dname, 4, pos };
		info[ax + index] = Info{ wname, 2, pos };
		info[al + index] = Info{ bname, 1, pos };
		if (!hname.empty())
			info[ah + index] = Info{ hname, 1, pos + 1 };
		pos += 8;
	};
	defineGPR(0, "rax", "eax", "ax", "al", "ah");
	defineGPR(1, "rcx", "ecx", "cx", "cl", "ch");
	defineGPR(2, "rdx", "edx", "dx", "dl", "dh");
	defineGPR(3, "rbx", "ebx", "bx", "bl", "bh");
	defineGPR(4, "rsp", "esp", "sp", "spl");
	defineGPR(5, "rbp", "ebp", "bp", "bpl");
	defineGPR(6, "rsi", "esi", "si", "sil");
	defineGPR(7, "rdi", "edi", "di", "dil");
	defineGPR(8, "r8", "r8d", "r8w", "r8b");
	defineGPR(9, "r9", "r9d", "r9w", "r9b");
	defineGPR(10, "r10", "r10d", "r10w", "r10b");
	defineGPR(11, "r11", "r11d", "r11w", "r11b");
	defineGPR(12, "r12", "r12d", "r12w", "r12b");
	defineGPR(13, "r13", "r13d", "r13w", "r13b");
	defineGPR(14, "r14", "r14d", "r14w", "r14b");
	defineGPR(15, "r15", "r15d", "r15w", "r15b");

	auto defineXMM = [&](int index, std::string_view zname, std::string_view yname, std::string_view xname) {
		info[zmm0 + index] = Info{ zname, 64, pos };
		info[ymm0 + index] = Info{ yname, 32, pos };
		info[xmm0 + index] = Info{ xname, 16, pos };
		pos += 64;
	};
	defineXMM(0, "zmm0", "ymm0", "xmm0");
	defineXMM(1, "zmm1", "ymm1", "xmm1");
	defineXMM(2, "zmm2", "ymm2", "xmm2");
	defineXMM(3, "zmm3", "ymm3", "xmm3");
	defineXMM(4, "zmm4", "ymm4", "xmm4");
	defineXMM(5, "zmm5", "ymm5", "xmm5");
	defineXMM(6, "zmm6", "ymm6", "xmm6");
	defineXMM(7, "zmm7", "ymm7", "xmm7");
	defineXMM(8, "zmm8", "ymm8", "xmm8");
	defineXMM(9, "zmm9", "ymm9", "xmm9");
	defineXMM(10, "zmm10", "ymm10", "xmm10");
	defineXMM(11, "zmm11", "ymm11", "xmm11");
	defineXMM(12, "zmm12", "ymm12", "xmm12");
	defineXMM(13, "zmm13", "ymm13", "xmm13");
	defineXMM(14, "zmm14", "ymm14", "xmm14");
	defineXMM(15, "zmm15", "ymm15", "xmm15");
	defineXMM(16, "zmm16", "ymm16", "xmm16");
	defineXMM(17, "zmm17", "ymm17", "xmm17");
	defineXMM(18, "zmm18", "ymm18", "xmm18");
	defineXMM(19, "zmm19", "ymm19", "xmm19");
	defineXMM(20, "zmm20", "ymm20", "xmm20");
	defineXMM(21, "zmm21", "ymm21", "xmm21");
	defineXMM(22, "zmm22", "ymm22", "xmm22");
	defineXMM(23, "zmm23", "ymm23", "xmm23");
	defineXMM(24, "zmm24", "ymm24", "xmm24");
	defineXMM(25, "zmm25", "ymm25", "xmm25");
	defineXMM(26, "zmm26", "ymm26", "xmm26");
	defineXMM(27, "zmm27", "ymm27", "xmm27");
	defineXMM(28, "zmm28", "ymm28", "xmm28");
	defineXMM(29, "zmm29", "ymm29", "xmm29");
	defineXMM(30, "zmm30", "ymm30", "xmm30");
	defineXMM(31, "zmm31", "ymm31", "xmm31");

	return info;
}();

}

// formatters
using namespace x86;

export template<> struct std::formatter<Reg>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
	auto format(const Reg& obj, format_context& ctx) const { return ranges::copy(obj.name(), ctx.out()).out; }
};
