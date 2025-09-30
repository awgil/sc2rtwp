module;

#include <common/bitfield_ops.h>
#include <common/win_headers.h>
#include <capstone/capstone.h>
#include <cassert>

export module unpack.analysis;

import std;
import common;
import unpack.pe_binary;
import unpack.function;

// an uninterrupted sequence of instructions; each basic block has only one entry point
// topologically sorted (aka reverse post-order), so:
// - all non-loop predecessors are ordered before a given block
// - two disjoint instruction ranges that can conceptually be combined into a single basic block have successive indices
export struct AnalysisBlock
{
	const FunctionBlock* fblock;
	SmallVector<int, 2> successors;
	SmallVector<int, 2> predecessors;
	SmallVector<int, 2> dominanceFrontier;
	int immediateDominator = -1;
};

struct AnalysisPointer
{
	int addressSpace;
	int offset;
};
AnalysisPointer operator+(AnalysisPointer l, i32 r) { return{ l.addressSpace, l.offset + r }; }
AnalysisPointer& operator+=(AnalysisPointer& l, i32 r) { l.offset += r; return l; }
AnalysisPointer operator-(AnalysisPointer l, i32 r) { return{ l.addressSpace, l.offset - r }; }
AnalysisPointer& operator-=(AnalysisPointer& l, i32 r) { l.offset -= r; return l; }

struct AnalysisExpressionRef
{
	size_t index;
};

union AnalysisValue
{
	i64 constant;
	AnalysisPointer ptr;
	AnalysisExpressionRef expr;
};

enum class AnalysisValueType : u8
{
	Unknown,
	Constant,
	Pointer,
	Expression,
};

struct AnalysisValueWithType
{
	AnalysisValueType type;
	AnalysisValue value;

	AnalysisValueWithType() : type(AnalysisValueType::Unknown), value(0) {}
	AnalysisValueWithType(i64 value) : type(AnalysisValueType::Constant), value(value) {}
	AnalysisValueWithType(AnalysisPointer value) : type(AnalysisValueType::Pointer), value{ .ptr = value } {}
	AnalysisValueWithType(AnalysisExpressionRef value) : type(AnalysisValueType::Expression), value{ .expr = value } {}
	AnalysisValueWithType(AnalysisValueType type, AnalysisValue value) : type(type), value(value) {}
};

enum class AnalysisExpressionOp : u8
{
	Invalid,

	// unary expressions
	Deref, // = *op1
	Neg, // = -op1
	Not, // = ~op1
	LastUnary,

	// binary expressions
	Add, // = op1 + op2
	Xor, // = op1 ^ op2
	LastBinary,
};

// note: for commutative binary ops, if one of the operands is constant, it's always second one
struct AnalysisExpression
{
	rva_t rva = 0;
	int blockIndex = 0;
	int size = 0; // byte width of the result (TODO: do we care here?..)
	AnalysisExpressionOp op = AnalysisExpressionOp::Invalid;
	AnalysisValueType operandType[2] = {};
	AnalysisValue operandValue[2] = {};

	AnalysisExpression() = default;

	// binary op
	AnalysisExpression(int size, AnalysisValueWithType lhs, AnalysisExpressionOp op, AnalysisValueWithType rhs)
		: size(size), op(op)
	{
		setOperand(0, lhs);
		setOperand(1, rhs);
	}

	// unary op
	AnalysisExpression(int size, AnalysisExpressionOp op, AnalysisValueWithType value) : AnalysisExpression(size, value, op, {}) {}

	AnalysisValueWithType getOperand(int index) const { return{ operandType[index], operandValue[index] }; }
	void setOperand(int index, AnalysisValueWithType value)
	{
		operandType[index] = value.type;
		operandValue[index] = value.value;
	}
};

// known memory state
struct AnalysisState
{
	std::vector<SimpleRangeMap<int, AnalysisValueWithType>> addressSpaces; // for each address space: key = offset, value = variable state

	enum StandardAddressSpaces
	{
		AS_Register, // offset depends on register id
		AS_Global, // offset = rva
		AS_Stack, // offset 0 is retaddr
		AS_TEB, // gs:[offset], contains TEB
		AS_PEB,
		AS_LoaderData, // in PEB
		AS_LoaderDataEntry,

		AS_Count
	};

	static AnalysisState buildEntryState()
	{
		AnalysisState res;
		res.addressSpaces.resize(AS_Count);
		auto [rspStart, rspEnd] = registerToRange(X86_REG_RSP);
		res.addressSpaces[AS_Register].insert({ rspStart, rspEnd, AnalysisPointer{ AS_Stack }});
		res.addressSpaces[AS_TEB].insert({ 0x30, 0x38, AnalysisPointer{ AS_TEB } }); // NtTib.Self
		res.addressSpaces[AS_TEB].insert({ 0x60, 0x68, AnalysisPointer{ AS_PEB } });
		res.addressSpaces[AS_PEB].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderData } });
		res.addressSpaces[AS_LoaderData].insert({ 0x10, 0x18, AnalysisPointer{ AS_LoaderDataEntry } }); // InLoadOrderModuleList
		res.addressSpaces[AS_LoaderData].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderDataEntry } });
		res.addressSpaces[AS_LoaderData].insert({ 0x20, 0x28, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } }); // InMemoryOrderModuleList
		res.addressSpaces[AS_LoaderData].insert({ 0x28, 0x30, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } });
		res.addressSpaces[AS_LoaderData].insert({ 0x30, 0x38, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } }); // InInitializationOrderModuleList
		res.addressSpaces[AS_LoaderData].insert({ 0x38, 0x40, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } });
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x0, 0x8, AnalysisPointer{ AS_LoaderDataEntry } }); // InLoadOrderLinks
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x8, 0x10, AnalysisPointer{ AS_LoaderDataEntry } });
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x10, 0x18, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } }); // InMemoryOrderLinks
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } });
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x20, 0x28, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } }); // InInitializationOrderLinks
		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x28, 0x30, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } });
		return res;
	}

	static std::pair<int, int> registerToOffsetSize(x86_reg reg)
	{
		static constexpr int gprStart = 0;
		static constexpr int gprSize = 8;
		static auto gprOffset = [](int index) { return gprStart + index * gprSize; };
		static auto gprPair = [](int index, int size, int offset = 0) { return std::make_pair(gprOffset(index) + offset, size); };
		static constexpr int xmmStart = gprOffset(16);
		static constexpr int xmmSize = 64;
		static auto xmmOffset = [](int index) { return xmmStart + index * xmmSize; };
		static auto xmmPair = [](int index, int size) { return std::make_pair(xmmOffset(index), size); };
		// unsupported: flags, ip, segment regs, cr, dr, fpu, mmx, k (avx), bnd
		switch (reg)
		{
		case X86_REG_AL: return gprPair(0, 1);
		case X86_REG_AH: return gprPair(0, 1, 1);
		case X86_REG_AX: return gprPair(0, 2);
		case X86_REG_EAX: return gprPair(0, 4);
		case X86_REG_RAX: return gprPair(0, 8);
		case X86_REG_CL: return gprPair(1, 1);
		case X86_REG_CH: return gprPair(1, 1, 1);
		case X86_REG_CX: return gprPair(1, 2);
		case X86_REG_ECX: return gprPair(1, 4);
		case X86_REG_RCX: return gprPair(1, 8);
		case X86_REG_DL: return gprPair(2, 1);
		case X86_REG_DH: return gprPair(2, 1, 1);
		case X86_REG_DX: return gprPair(2, 2);
		case X86_REG_EDX: return gprPair(2, 4);
		case X86_REG_RDX: return gprPair(2, 8);
		case X86_REG_BL: return gprPair(3, 1);
		case X86_REG_BH: return gprPair(3, 1, 1);
		case X86_REG_BX: return gprPair(3, 2);
		case X86_REG_EBX: return gprPair(3, 4);
		case X86_REG_RBX: return gprPair(3, 8);
		case X86_REG_SPL: return gprPair(4, 1);
		case X86_REG_SP: return gprPair(4, 2);
		case X86_REG_ESP: return gprPair(4, 4);
		case X86_REG_RSP: return gprPair(4, 8);
		case X86_REG_BPL: return gprPair(5, 1);
		case X86_REG_BP: return gprPair(5, 2);
		case X86_REG_EBP: return gprPair(5, 4);
		case X86_REG_RBP: return gprPair(5, 8);
		case X86_REG_SIL: return gprPair(6, 1);
		case X86_REG_SI: return gprPair(6, 2);
		case X86_REG_ESI: return gprPair(6, 4);
		case X86_REG_RSI: return gprPair(6, 8);
		case X86_REG_DIL: return gprPair(7, 1);
		case X86_REG_DI: return gprPair(7, 2);
		case X86_REG_EDI: return gprPair(7, 4);
		case X86_REG_RDI: return gprPair(7, 8);
		case X86_REG_R8B: return gprPair(8, 1);
		case X86_REG_R8W: return gprPair(8, 2);
		case X86_REG_R8D: return gprPair(8, 4);
		case X86_REG_R8: return gprPair(8, 8);
		case X86_REG_R9B: return gprPair(9, 1);
		case X86_REG_R9W: return gprPair(9, 2);
		case X86_REG_R9D: return gprPair(9, 4);
		case X86_REG_R9: return gprPair(9, 8);
		case X86_REG_R10B: return gprPair(10, 1);
		case X86_REG_R10W: return gprPair(10, 2);
		case X86_REG_R10D: return gprPair(10, 4);
		case X86_REG_R10: return gprPair(10, 8);
		case X86_REG_R11B: return gprPair(11, 1);
		case X86_REG_R11W: return gprPair(11, 2);
		case X86_REG_R11D: return gprPair(11, 4);
		case X86_REG_R11: return gprPair(11, 8);
		case X86_REG_R12B: return gprPair(12, 1);
		case X86_REG_R12W: return gprPair(12, 2);
		case X86_REG_R12D: return gprPair(12, 4);
		case X86_REG_R12: return gprPair(12, 8);
		case X86_REG_R13B: return gprPair(13, 1);
		case X86_REG_R13W: return gprPair(13, 2);
		case X86_REG_R13D: return gprPair(13, 4);
		case X86_REG_R13: return gprPair(13, 8);
		case X86_REG_R14B: return gprPair(14, 1);
		case X86_REG_R14W: return gprPair(14, 2);
		case X86_REG_R14D: return gprPair(14, 4);
		case X86_REG_R14: return gprPair(14, 8);
		case X86_REG_R15B: return gprPair(15, 1);
		case X86_REG_R15W: return gprPair(15, 2);
		case X86_REG_R15D: return gprPair(15, 4);
		case X86_REG_R15: return gprPair(15, 8);
		case X86_REG_XMM0: return xmmPair(0, 16);
		case X86_REG_YMM0: return xmmPair(0, 32);
		case X86_REG_ZMM0: return xmmPair(0, 64);
		case X86_REG_XMM1: return xmmPair(1, 16);
		case X86_REG_YMM1: return xmmPair(1, 32);
		case X86_REG_ZMM1: return xmmPair(1, 64);
		case X86_REG_XMM2: return xmmPair(2, 16);
		case X86_REG_YMM2: return xmmPair(2, 32);
		case X86_REG_ZMM2: return xmmPair(2, 64);
		case X86_REG_XMM3: return xmmPair(3, 16);
		case X86_REG_YMM3: return xmmPair(3, 32);
		case X86_REG_ZMM3: return xmmPair(3, 64);
		case X86_REG_XMM4: return xmmPair(4, 16);
		case X86_REG_YMM4: return xmmPair(4, 32);
		case X86_REG_ZMM4: return xmmPair(4, 64);
		case X86_REG_XMM5: return xmmPair(5, 16);
		case X86_REG_YMM5: return xmmPair(5, 32);
		case X86_REG_ZMM5: return xmmPair(5, 64);
		case X86_REG_XMM6: return xmmPair(6, 16);
		case X86_REG_YMM6: return xmmPair(6, 32);
		case X86_REG_ZMM6: return xmmPair(6, 64);
		case X86_REG_XMM7: return xmmPair(7, 16);
		case X86_REG_YMM7: return xmmPair(7, 32);
		case X86_REG_ZMM7: return xmmPair(7, 64);
		case X86_REG_XMM8: return xmmPair(8, 16);
		case X86_REG_YMM8: return xmmPair(8, 32);
		case X86_REG_ZMM8: return xmmPair(8, 64);
		case X86_REG_XMM9: return xmmPair(9, 16);
		case X86_REG_YMM9: return xmmPair(9, 32);
		case X86_REG_ZMM9: return xmmPair(9, 64);
		case X86_REG_XMM10: return xmmPair(10, 16);
		case X86_REG_YMM10: return xmmPair(10, 32);
		case X86_REG_ZMM10: return xmmPair(10, 64);
		case X86_REG_XMM11: return xmmPair(11, 16);
		case X86_REG_YMM11: return xmmPair(11, 32);
		case X86_REG_ZMM11: return xmmPair(11, 64);
		case X86_REG_XMM12: return xmmPair(12, 16);
		case X86_REG_YMM12: return xmmPair(12, 32);
		case X86_REG_ZMM12: return xmmPair(12, 64);
		case X86_REG_XMM13: return xmmPair(13, 16);
		case X86_REG_YMM13: return xmmPair(13, 32);
		case X86_REG_ZMM13: return xmmPair(13, 64);
		case X86_REG_XMM14: return xmmPair(14, 16);
		case X86_REG_YMM14: return xmmPair(14, 32);
		case X86_REG_ZMM14: return xmmPair(14, 64);
		case X86_REG_XMM15: return xmmPair(15, 16);
		case X86_REG_YMM15: return xmmPair(15, 32);
		case X86_REG_ZMM15: return xmmPair(15, 64);
		case X86_REG_XMM16: return xmmPair(16, 16);
		case X86_REG_YMM16: return xmmPair(16, 32);
		case X86_REG_ZMM16: return xmmPair(16, 64);
		case X86_REG_XMM17: return xmmPair(17, 16);
		case X86_REG_YMM17: return xmmPair(17, 32);
		case X86_REG_ZMM17: return xmmPair(17, 64);
		case X86_REG_XMM18: return xmmPair(18, 16);
		case X86_REG_YMM18: return xmmPair(18, 32);
		case X86_REG_ZMM18: return xmmPair(18, 64);
		case X86_REG_XMM19: return xmmPair(19, 16);
		case X86_REG_YMM19: return xmmPair(19, 32);
		case X86_REG_ZMM19: return xmmPair(19, 64);
		case X86_REG_XMM20: return xmmPair(20, 16);
		case X86_REG_YMM20: return xmmPair(20, 32);
		case X86_REG_ZMM20: return xmmPair(20, 64);
		case X86_REG_XMM21: return xmmPair(21, 16);
		case X86_REG_YMM21: return xmmPair(21, 32);
		case X86_REG_ZMM21: return xmmPair(21, 64);
		case X86_REG_XMM22: return xmmPair(22, 16);
		case X86_REG_YMM22: return xmmPair(22, 32);
		case X86_REG_ZMM22: return xmmPair(22, 64);
		case X86_REG_XMM23: return xmmPair(23, 16);
		case X86_REG_YMM23: return xmmPair(23, 32);
		case X86_REG_ZMM23: return xmmPair(23, 64);
		case X86_REG_XMM24: return xmmPair(24, 16);
		case X86_REG_YMM24: return xmmPair(24, 32);
		case X86_REG_ZMM24: return xmmPair(24, 64);
		case X86_REG_XMM25: return xmmPair(25, 16);
		case X86_REG_YMM25: return xmmPair(25, 32);
		case X86_REG_ZMM25: return xmmPair(25, 64);
		case X86_REG_XMM26: return xmmPair(26, 16);
		case X86_REG_YMM26: return xmmPair(26, 32);
		case X86_REG_ZMM26: return xmmPair(26, 64);
		case X86_REG_XMM27: return xmmPair(27, 16);
		case X86_REG_YMM27: return xmmPair(27, 32);
		case X86_REG_ZMM27: return xmmPair(27, 64);
		case X86_REG_XMM28: return xmmPair(28, 16);
		case X86_REG_YMM28: return xmmPair(28, 32);
		case X86_REG_ZMM28: return xmmPair(28, 64);
		case X86_REG_XMM29: return xmmPair(29, 16);
		case X86_REG_YMM29: return xmmPair(29, 32);
		case X86_REG_ZMM29: return xmmPair(29, 64);
		case X86_REG_XMM30: return xmmPair(30, 16);
		case X86_REG_YMM30: return xmmPair(30, 32);
		case X86_REG_ZMM30: return xmmPair(30, 64);
		case X86_REG_XMM31: return xmmPair(31, 16);
		case X86_REG_YMM31: return xmmPair(31, 32);
		case X86_REG_ZMM31: return xmmPair(31, 64);
		default: throw std::exception("Unsupported register");
		}
	}

	static std::pair<int, int> registerToRange(x86_reg reg)
	{
		auto [begin, size] = registerToOffsetSize(reg);
		return{ begin, begin + size };
	}
};

export class AnalyzedFunction
{
public:
	AnalyzedFunction(const FunctionInfo& func)
	{
		// first build a 1:1 mapping of raw function blocks to basic blocks
		std::vector<int> mapping(func.blocks().size());
		mBlocks.resize(func.blocks().size());
		int lastTopoIndex = mBlocks.size();
		visitNewBlock(func, 0, lastTopoIndex, mapping);
		assert(lastTopoIndex == 0);
		assert(mapping[0] == 0);

		// remap successor indices and determine predecessors
		for (int i = 0; i < mBlocks.size(); ++i)
		{
			auto& b = mBlocks[i];
			for (auto& succ : b.successors)
			{
				succ = mapping[succ];
				mBlocks[succ].predecessors.push_back(i);
			}
			std::ranges::sort(b.successors);
		}

		calculateImmediateDominators();
		calculateDominanceFrontiers();

		// TODO: entry state should be customizable...
		emulate(AnalysisState::buildEntryState());
	}

private:
	void visitNewBlock(const FunctionInfo& func, int blockIndex, int& lastTopoIndex, std::vector<int>& mapping)
	{
		assert(mapping[blockIndex] == 0);
		mapping[blockIndex] = -1; // mark as being visited
		auto& fblock = func.blocks()[blockIndex];

		// convert successor rvas to function block indices
		// later we'll convert that to base block indices, after we place them all
		SmallVector<int, 2> succTopoIndices(fblock.successors | std::ranges::views::transform([&](const FunctionEdge& edge) { return func.blocks().findIndex(edge.rva); }));

		// now visit all successors that haven't been visited yet
		for (auto succ : succTopoIndices | std::ranges::views::reverse)
		{
			if (mapping[succ] == 0)
			{
				visitNewBlock(func, succ, lastTopoIndex, mapping);
			}
		}

		assert(lastTopoIndex > 0);
		auto& assignedBlock = mBlocks[--lastTopoIndex];
		mapping[blockIndex] = lastTopoIndex;
		assert(!assignedBlock.fblock);
		assignedBlock.fblock = &fblock;
		assignedBlock.successors = std::move(succTopoIndices);
	}

	void calculateImmediateDominators()
	{
		// see http://www.hipersoft.rice.edu/grads/publications/dom14.pdf
		mBlocks[0].immediateDominator = 0; // note: this is not great, but whatever...
		bool needAnotherIteration = true;
		while (needAnotherIteration)
		{
			needAnotherIteration = false;
			for (int i = 1; i < mBlocks.size(); ++i)
			{
				auto& b = mBlocks[i];
				int newIdom = b.predecessors[0];
				for (int p : b.predecessors | std::ranges::views::drop(1))
				{
					if (mBlocks[p].immediateDominator >= 0)
					{
						newIdom = findCommonDominator(p, newIdom);
					}
				}
				if (b.immediateDominator != newIdom)
				{
					b.immediateDominator = newIdom;
					needAnotherIteration = true;
				}
			}
		}
	}

	int findCommonDominator(int i1, int i2) const
	{
		while (i1 != i2)
		{
			while (i1 > i2)
				i1 = mBlocks[i1].immediateDominator;
			while (i2 > i1)
				i2 = mBlocks[i2].immediateDominator;
		}
		return i1;
	}

	void calculateDominanceFrontiers()
	{
		for (int i = 0; i < mBlocks.size(); ++i)
		{
			auto& b = mBlocks[i];
			for (auto p : b.predecessors)
			{
				while (p != b.immediateDominator)
				{
					auto& pred = mBlocks[p];
					if (!pred.dominanceFrontier.empty() && pred.dominanceFrontier.back() == i)
						break; // i was already added to the dominance frontier of p (and thus it's idom chain) on previous iterations
					pred.dominanceFrontier.push_back(i);
					p = pred.immediateDominator;
				}
			}
		}
	}

	AnalysisState buildEntryState(int iBlock)
	{
		auto& block = mBlocks[iBlock];
		assert(!block.predecessors.empty());
		AnalysisState state = mExitStates[block.predecessors.front()]; // TODO: move if this is the last successor...
		for (auto i : block.predecessors | std::ranges::views::drop(1))
		{
			if (i >= iBlock)
				continue; // loop link
			ensure(false); // TODO: merge...
		}
		return state;
	}

	void emulate(AnalysisState&& initialState)
	{
		// initial setup
		mExitStates.resize(mBlocks.size());

		mExitStates[0] = std::move(initialState);
		emulateBlock(0);
		for (int i = 1; i < mBlocks.size(); ++i)
		{
			mExitStates[i] = buildEntryState(i);
			emulateBlock(i);
		}
	}

	void emulateBlock(int iBlock)
	{
		mCurrentBlockIndex = iBlock;
		for (auto& isn : mBlocks[iBlock].fblock->instructions)
			emulateInstruction(isn);
	}

	void emulateInstruction(const Instruction& isn)
	{
		switch (isn.mnem)
		{
		case X86_INS_MOV: return emulateMov(isn);
		case X86_INS_PUSH: return emulatePush(isn);
		case X86_INS_LEA: return emulateLea(isn);
		case X86_INS_ADD: return emulateAdd(isn);
		case X86_INS_SUB: return emulateSub(isn);
		case X86_INS_XOR: return emulateXor(isn);
		case X86_INS_BTC: return emulateBtc(isn);

		case X86_INS_CMP:
		case X86_INS_TEST:
			return; // no-op, unless we start caring about flags

		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JB:
		case X86_INS_JAE:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JBE:
		case X86_INS_JA:
		case X86_INS_JL:
		case X86_INS_JGE:
		case X86_INS_JLE:
		case X86_INS_JG:
			return; // conditional jumps...

		case X86_INS_NOP:
		case X86_INS_JMP:
			break;
		default:
			__debugbreak();
		}
	}

	void emulateLea(const Instruction& isn)
	{
		assert(isn.opcount == 2 && isn.ops[0].type == OperandType::Reg && (isn.ops[1].type == OperandType::Mem || isn.ops[1].type == OperandType::MemRVA));
		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8);
		auto dest = operandAddress(isn, isn.ops[0]);
		auto value = operandAddress(isn, isn.ops[1]);
		derefStore(dest, isn.ops[0].size, isn.rva, value);
	}

	void emulateMov(const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == isn.ops[1].size);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
			return; // mov x, x is a no-op
		auto dest = operandAddress(isn, isn.ops[0]);
		auto value = read(isn, isn.ops[1]);
		derefStore(dest, isn.ops[0].size, isn.rva, value);
	}

	void emulateAdd(const Instruction& isn)
	{
		// TODO: add x, x ==> x *= 2 ??? or this should be handled by simplifier?
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == isn.ops[1].size);
		auto dest = operandAddress(isn, isn.ops[0]);
		auto value = read(isn, isn.ops[1]);
		auto modified = simplifyAdd(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), value);
		derefStore(dest, isn.ops[0].size, isn.rva, modified);
	}

	void emulateSub(const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == isn.ops[1].size);
		auto dest = operandAddress(isn, isn.ops[0]);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
		{
			// sub x, x ==> x = 0
			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
			derefStore(dest, isn.ops[0].size, isn.rva, 0);
		}
		else
		{
			assert(isn.ops[0].size == 8); // TODO: sub reg,xxx with non-8 size
			auto value = read(isn, isn.ops[1]);
			auto modified = simplifyAdd(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), simplifyNeg(isn.rva, isn.ops[1].size, value));
			derefStore(dest, isn.ops[0].size, isn.rva, modified);
		}
	}

	void emulateXor(const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == isn.ops[1].size);
		auto dest = operandAddress(isn, isn.ops[0]);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
		{
			// xor x, x ==> x = 0
			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
			derefStore(dest, isn.ops[0].size, isn.rva, 0);
		}
		else
		{
			auto value = read(isn, isn.ops[1]);
			auto modified = simplifyXor(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), value);
			derefStore(dest, isn.ops[0].size, isn.rva, modified);
		}
	}

	void emulatePush(const Instruction& isn)
	{
		assert(isn.opcount == 1 && isn.ops[0].size == 8);
		// push x ==> sub rsp, 8 + mov [rsp], x
		auto rsp = AnalysisPointer{ AnalysisState::AS_Register, AnalysisState::registerToOffsetSize(X86_REG_RSP).first };
		auto rspValue = derefLoad(rsp, 8, isn.rva);
		assert(rspValue.type == AnalysisValueType::Pointer && rspValue.value.ptr.addressSpace == AnalysisState::AS_Stack);
		rspValue.value.ptr -= 8;
		derefStore(rsp, 8, isn.rva, rspValue);
		derefStore(rspValue, isn.ops[0].size, isn.rva, read(isn, isn.ops[0]));
	}

	void emulateBtc(const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[1].type == OperandType::Imm); // TODO: handle version with register?..
		assert(isn.ops[1].size == 1);
		// btc x, imm ==> xor x, (1 << imm)
		auto dest = operandAddress(isn, isn.ops[0]);
		auto modified = simplifyXor(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), 1ll << isn.imm);
		derefStore(dest, isn.ops[0].size, isn.rva, modified);
	}

	// think what 'lea' does, but also supports registers - convert reg/mem operand to an 'address'
	// note that it might return any type (e.g. constant if operand is [addr], or an expression ref if operand is something like [rcx] where rcx value is unknown
	// registers are converted to pointers into 'register file' address space
	AnalysisValueWithType operandAddress(const Instruction& isn, const Operand& operand)
	{
		if (operand.type == OperandType::Reg)
		{
			auto [offset, size] = AnalysisState::registerToOffsetSize(operand.reg);
			assert(size == operand.size);
			return AnalysisPointer{ AnalysisState::AS_Register, offset };
		}
		else
		{
			assert(operand.type == OperandType::Mem || operand.type == OperandType::MemRVA);
			auto res = operandAddressBase(isn, operand.type == OperandType::MemRVA);
			auto off = operandAddressOffset(isn);
			switch (res.type)
			{
			case AnalysisValueType::Constant:
				res.value.constant += off;
				return res;
			case AnalysisValueType::Pointer:
				res.value.ptr.offset += off;
				return res;
			case AnalysisValueType::Expression:
				return simplifyAdd(isn.rva, 8, res, off);
			default:
				__debugbreak();
				return{};
			}
		}
	}

	AnalysisValueWithType operandAddressBase(const Instruction& isn, bool rvaBase)
	{
		if (rvaBase)
		{
			assert(isn.mem.segment == X86_REG_INVALID);
			return AnalysisPointer{ AnalysisState::AS_Global };
		}
		else if (isn.mem.segment == X86_REG_INVALID)
		{
			assert(isn.mem.base != X86_REG_INVALID);
			auto [offset, size] = AnalysisState::registerToOffsetSize(isn.mem.base);
			assert(size == 8);
			return derefLoad(AnalysisPointer{ AnalysisState::AS_Register, offset }, size, isn.rva);
		}
		else if (isn.mem.segment == X86_REG_GS)
		{
			auto offset = 0;
			if (isn.mem.base != X86_REG_INVALID)
			{
				auto [boffset, bsize] = AnalysisState::registerToOffsetSize(isn.mem.base);
				assert(bsize == 8);
				auto bval = derefLoad(AnalysisPointer{ AnalysisState::AS_Register, boffset }, bsize, isn.rva);
				if (bval.type == AnalysisValueType::Constant)
					offset += bval.value.constant;
				else
					__debugbreak();
			}
			return AnalysisPointer{ AnalysisState::AS_TEB, offset };
		}
		else
		{
			__debugbreak(); // TODO
			return{};
		}
	}

	// TODO: should it return AVWT instead?..
	i32 operandAddressOffset(const Instruction& isn)
	{
		auto offset = isn.mem.disp;
		if (isn.mem.index != X86_REG_INVALID && isn.mem.scale != 0)
		{
			auto [ioffset, isize] = AnalysisState::registerToOffsetSize(isn.mem.index);
			assert(isize == 8);
			auto ival = derefLoad(AnalysisPointer{ AnalysisState::AS_Register, ioffset }, isize, isn.rva);
			if (ival.type == AnalysisValueType::Constant)
				offset += ival.value.constant;
			else
				__debugbreak();
		}
		return offset;
	}

	// load value stored at specified address
	AnalysisValueWithType derefLoad(AnalysisValueWithType address, int size, rva_t rva)
	{
		if (address.type != AnalysisValueType::Pointer)
			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address)); // fallback, we don't know how to dereference non-pointer properly

		auto entryEnd = address.value.ptr.offset + size;
		auto& space = mExitStates[mCurrentBlockIndex].addressSpaces[address.value.ptr.addressSpace];
		auto next = space.findNext(address.value.ptr.offset);
		if (next != space.end() && next->begin < entryEnd)
		{
			// partial overlap with high bytes
			// TODO: merge constants...
			__debugbreak();
			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
		}

		if (next == space.begin() || (next - 1)->end <= address.value.ptr.offset)
		{
			// read of fully uninitialized memory
			// add a new expression, so that subsequent reads return same one
			auto value = addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
			space.insert({ address.value.ptr.offset, address.value.ptr.offset + size, value });
			return value;
		}

		auto prev = next - 1;
		if (prev->begin < address.value.ptr.offset)
		{
			// partial overlap with low bytes
			// TODO: merge constants...
			__debugbreak();
			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
		}

		if (prev->end == entryEnd)
		{
			// good path
			return prev->value;
		}
		else if (prev->end < entryEnd)
		{
			// read of partially written value - what to do?..
			__debugbreak();
			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
		}
		else if (prev->value.type != AnalysisValueType::Constant)
		{
			// TODO: partial read of non-constant - what to do?.. can have something like & 0xFFFF....
			__debugbreak();
			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
		}
		else
		{
			auto value = prev->value.value.constant & ((1ull << 8 * size) - 1);
			return makeConstant(value, size);
		}
	}

	// store specified value at specified address
	void derefStore(AnalysisValueWithType address, int size, rva_t rva, AnalysisValueWithType value)
	{
		assert(value.type != AnalysisValueType::Unknown);
		ensure(value.type != AnalysisValueType::Pointer || size == 8); // chopping pointers is probably not correct?..
		ensure(value.type != AnalysisValueType::Expression || mExpressions[value.value.expr.index].size == size); // ???

		if (address.type != AnalysisValueType::Pointer)
		{
			__debugbreak(); // TODO: if we care, record off the side - but we can't really update the state anyway (so any potential aliasing is lost)
			return;
		}

		if (address.value.ptr.addressSpace == AnalysisState::AS_Register && size == 4)
		{
			// dword register writes automatically clear high dword
			size = 8;
			if (value.type == AnalysisValueType::Constant)
				value.value.constant &= 0xFFFFFFFF;
			// TODO: for expressions - consider wrapping into a zero-extend unary op?.. might complicate things a bit...
		}

		auto entryEnd = address.value.ptr.offset + size;
		auto& space = mExitStates[mCurrentBlockIndex].addressSpaces[address.value.ptr.addressSpace];
		auto next = space.findNext(address.value.ptr.offset);
		if (next != space.end() && next->begin < entryEnd)
		{
			// we have some partial overlaps - full overlaps can be deleted (since they are fully overwritten)
			auto overlapEnd = next + 1;
			while (overlapEnd != space.end() && overlapEnd->end <= entryEnd)
				++overlapEnd;

			if (overlapEnd != space.end() && overlapEnd->begin < entryEnd)
			{
				// partial overlap - some low bytes are to be discarded
				// TODO: implement as generic byte-extract / shift?..
				if (overlapEnd->value.type == AnalysisValueType::Constant)
				{
					space.edit(overlapEnd).value.value.constant >>= 8 * (entryEnd - overlapEnd->begin);
					space.shrink(entryEnd, overlapEnd->end, overlapEnd);
				}
				else
				{
					__debugbreak();
					++overlapEnd; // forgetting stuff always works...
				}
			}

			next = space.erase(next, overlapEnd);
		}
		// at this point, if next exists, it does not overlap the entry

		if (next == space.begin() || (next - 1)->end <= address.value.ptr.offset)
		{
			// no overlaps, just insert new entry
			space.insert({ address.value.ptr.offset, entryEnd, value }, next);
			return;
		}

		// ok, so there's some overlap between existing and new ranges - we might have bytes to chop on either side, and then might need to extend the remaining entry
		auto prev = next - 1;
		if (prev->begin < address.value.ptr.offset)
		{
			// insert new entry before prev containing chopped off low bytes
			// TODO: implement this generically?
			if (prev->value.type == AnalysisValueType::Constant)
			{
				auto addr = prev->begin;
				AnalysisValueWithType low = prev->value.value.constant & ((1ull << 8 * (address.value.ptr.offset - prev->begin)) - 1);
				space.shrink(address.value.ptr.offset, prev->end, prev);
				prev = space.insert({ addr, address.value.ptr.offset, low }, prev);
			}
			else
			{
				// just shrink the entry, effectively forgetting low bytes
				__debugbreak();
				space.shrink(address.value.ptr.offset, prev->end, prev);
			}
		}

		if (prev->end > entryEnd)
		{
			// insert new entry after prev containing chopped off high bytes
			// TODO: implement as generic byte-extract / shift?..
			if (prev->value.type == AnalysisValueType::Constant)
			{
				auto end = prev->end;
				AnalysisValueWithType high = prev->value.value.constant >> 8 * (end - entryEnd);
				space.shrink(prev->begin, entryEnd, prev);
				prev = space.insert({ entryEnd, end, high }, prev + 1) - 1;
			}
			else
			{
				// just shrink the entry, effectively forgetting high bytes
				__debugbreak();
				space.shrink(prev->begin, entryEnd, prev);
			}
		}

		if (prev->end < entryEnd)
		{
			// existing entry just needs to be extended - this is fine, we'll overwrite it fully
			space.extend(prev->begin, entryEnd, prev);
		}

		// happy path - existing entry covers exactly same region as new one, so just overwrite
		space.edit(prev).value = value;
	}

	// read value specified by an operand
	// if value is currently undefined, creates new expression implicitly
	AnalysisValueWithType read(const Instruction& isn, const Operand& operand)
	{
		switch (operand.type)
		{
		case OperandType::Invalid:
			return{};
		case OperandType::Imm:
			return makeConstant(isn.imm, operand.size);
		case OperandType::ImmRVA:
			return AnalysisPointer{ AnalysisState::AS_Global, static_cast<i32>(isn.imm) };
		default:
			return derefLoad(operandAddress(isn, operand), operand.size, isn.rva);
		}
	}

	AnalysisExpressionRef addExpression(rva_t rva, AnalysisExpression expr)
	{
		expr.rva = rva;
		expr.blockIndex = mCurrentBlockIndex;
		auto index = mExpressions.size();
		mExpressions.push_back(expr);
		return{ index };
	}

	AnalysisValueWithType makeConstant(i64 value, int size)
	{
		switch (size)
		{
		case 1: return (i8)value;
		case 2: return (i16)value;
		case 4: return (i32)value;
		case 8: return (i64)value;
		default: throw std::exception("Unexpected size");
		}
	}

	AnalysisValueWithType simplifyNeg(rva_t rva, int size, AnalysisValueWithType v)
	{
		if (v.type == AnalysisValueType::Constant)
			return makeConstant(-v.value.constant, size);

		if (v.type == AnalysisValueType::Expression)
		{
			auto& e = mExpressions[v.value.expr.index];
			switch (e.op)
			{
			case AnalysisExpressionOp::Neg: return e.getOperand(0); // -(-x) == x
			case AnalysisExpressionOp::Add: return simplifyAdd(rva, size, simplifyNeg(rva, size, e.getOperand(0)), simplifyNeg(rva, size, e.getOperand(1))); // -(a + b) == (-a) + (-b)
			}
		}

		return addExpression(rva, { size, AnalysisExpressionOp::Neg, v });
	}

	AnalysisValueWithType simplifyAdd(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
	{
		commAssocSwapIfNeeded(lhs, AnalysisExpressionOp::Add, rhs);

		if (lhs.type == AnalysisValueType::Constant)
		{
			assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
			return makeConstant(lhs.value.constant + rhs.value.constant, size);
		}

		if (lhs.type == AnalysisValueType::Pointer && rhs.type == AnalysisValueType::Constant)
		{
			return lhs.value.ptr + rhs.value.constant;
		}

		if (rhs.type == AnalysisValueType::Expression && mExpressions[rhs.value.expr.index].op == AnalysisExpressionOp::Add)
		{
			assert(lhs.type == AnalysisValueType::Expression && mExpressions[lhs.value.expr.index].op == AnalysisExpressionOp::Add); // otherwise we'd have swapped
			// (a + b) + (c + d) ==> ((a + b) + c) + d
			auto& r = mExpressions[rhs.value.expr.index];
			lhs = simplifyAdd(rva, size, lhs, r.getOperand(0));
			rhs = r.getOperand(1);
		}

		if (lhs.type == AnalysisValueType::Expression && mExpressions[lhs.value.expr.index].op == AnalysisExpressionOp::Add)
		{
			auto& l = mExpressions[lhs.value.expr.index];
			assert(l.operandType[1] != AnalysisValueType::Expression || mExpressions[l.operandValue[1].expr.index].op != AnalysisExpressionOp::Add); // this would violate associativity form
			if (rhs.type == AnalysisValueType::Constant && (l.operandType[1] == AnalysisValueType::Constant || l.operandType[1] == AnalysisValueType::Pointer))
			{
				// (x + ptr/c1) + c2 ==> x + (ptr/c1 + c2)
				rhs = simplifyAdd(rva, size, l.getOperand(1), rhs);
				assert(rhs.type == AnalysisValueType::Constant || rhs.type == AnalysisValueType::Pointer);
				lhs = l.getOperand(0);
				assert(lhs.type == AnalysisValueType::Pointer || lhs.type == AnalysisValueType::Expression);
			}
			else if (priorityForCommAssoc(l.getOperand(1), AnalysisExpressionOp::Add) < priorityForCommAssoc(rhs, AnalysisExpressionOp::Add))
			{
				// something like (x + const) + expr ==> (x + expr) + const
				lhs = simplifyAdd(rva, size, l.getOperand(0), rhs);
				rhs = l.getOperand(1);
			}
		}

		// TODO: ((a + b) + c) + (-a) ==> b + c
		// TODO: ptr(ASx) + neg(ptr(ASx)) ==> constant
		// TODO: a * b + c * b ==> (a + c) * b
		return addExpression(rva, { size, lhs, AnalysisExpressionOp::Add, rhs });
	}

	AnalysisValueWithType simplifyXor(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
	{
		commAssocSwapIfNeeded(lhs, AnalysisExpressionOp::Xor, rhs);

		if (lhs.type == AnalysisValueType::Constant)
		{
			assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
			return makeConstant(lhs.value.constant ^ rhs.value.constant, size);
		}

		if (rhs.type == AnalysisValueType::Expression && mExpressions[rhs.value.expr.index].op == AnalysisExpressionOp::Xor)
		{
			assert(lhs.type == AnalysisValueType::Expression && mExpressions[lhs.value.expr.index].op == AnalysisExpressionOp::Xor); // otherwise we'd have swapped
			// (a ^ b) ^ (c ^ d) ==> ((a ^ b) ^ c) ^ d
			auto& r = mExpressions[rhs.value.expr.index];
			lhs = simplifyXor(rva, size, lhs, r.getOperand(0));
			rhs = r.getOperand(1);
		}

		if (lhs.type == AnalysisValueType::Expression && mExpressions[lhs.value.expr.index].op == AnalysisExpressionOp::Xor)
		{
			auto& l = mExpressions[lhs.value.expr.index];
			assert(l.operandType[1] != AnalysisValueType::Expression || mExpressions[l.operandValue[1].expr.index].op != AnalysisExpressionOp::Xor); // this would violate associativity form
			if (rhs.type == AnalysisValueType::Constant && l.operandType[1] == AnalysisValueType::Constant)
			{
				// (x ^ c1) ^ c2 ==> x ^ (c1 ^ c2)
				rhs = l.operandValue[1].constant ^ rhs.value.constant;
				assert(rhs.type == AnalysisValueType::Constant);
				lhs = l.getOperand(0);
				assert(lhs.type == AnalysisValueType::Pointer || lhs.type == AnalysisValueType::Expression);
			}
			else if (priorityForCommAssoc(l.getOperand(1), AnalysisExpressionOp::Xor) < priorityForCommAssoc(rhs, AnalysisExpressionOp::Xor))
			{
				// something like (x ^ const) ^ expr ==> (x ^ expr) ^ const
				lhs = simplifyXor(rva, size, l.getOperand(0), rhs);
				rhs = l.getOperand(1);
			}
		}

		// TODO: ((a ^ b) ^ c) ^ a ==> b ^ c
		return addExpression(rva, { size, lhs, AnalysisExpressionOp::Xor, rhs });
	}

	// associativeness: nested is always on the left
	// commutativeness: constant > pointer > other-op expr > same-op expr priority for right-side, this simplifies constant propagation
	int priorityForCommAssoc(AnalysisValueWithType v, AnalysisExpressionOp op)
	{
		switch (v.type)
		{
		case AnalysisValueType::Constant: return 0;
		case AnalysisValueType::Pointer: return 1;
		case AnalysisValueType::Expression: return mExpressions[v.value.expr.index].op == op ? 3 : 2;
		default: throw std::exception("Bad type");
		}
	}

	void commAssocSwapIfNeeded(AnalysisValueWithType& lhs, AnalysisExpressionOp op, AnalysisValueWithType& rhs)
	{
		if (priorityForCommAssoc(lhs, op) < priorityForCommAssoc(rhs, op))
			std::swap(rhs, lhs);
	}

private:
	std::vector<AnalysisBlock> mBlocks; // sorted in topological (reverse-post) order
	std::vector<AnalysisState> mExitStates;
	std::vector<AnalysisExpression> mExpressions;
	int mCurrentBlockIndex = -1;
};
