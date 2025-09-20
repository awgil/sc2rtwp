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

// an uninterrupted sequence of instructions (potentially split into several disjoint ranges, with unconditional jumps between them)
// each basic block has only one entry point
export struct BasicBlock
{
	SmallVector<const FunctionBlock*, 1> fblocks; // in exec order
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

struct AnalysisVariableRef
{
	int index;
	int version;
};

union AnalysisValue
{
	i64 constant;
	AnalysisPointer ptr;
	AnalysisVariableRef var;
};

enum class AnalysisValueType : u8
{
	Unknown,
	Constant,
	Pointer,
	Deref,
};

struct AnalysisValueWithType
{
	AnalysisValueType type;
	AnalysisValue value;

	AnalysisValueWithType() : type(AnalysisValueType::Unknown), value(0) {}
	AnalysisValueWithType(i64 value) : type(AnalysisValueType::Constant), value(value) {}
	AnalysisValueWithType(AnalysisPointer value) : type(AnalysisValueType::Pointer), value{ .ptr = value } {}
	AnalysisValueWithType(AnalysisVariableRef value) : type(AnalysisValueType::Deref), value{ .var = value } {}
	AnalysisValueWithType(AnalysisValueType type, AnalysisValue value) : type(type), value(value) {}
};

enum class AnalysisValueOp : u8
{
	Assign, // = op1
	Add, // = op1 + op2
	Sub, // = op1 - op2
	Xor, // = op1 ^ op2
};

struct AnalysisVariableValue
{
	rva_t assignment = 0;
	int blockIndex = 0;
	int numRefs = 0; // if 0, this is a dead variable
	AnalysisValueOp op;
	// TODO: op size
	AnalysisValueType operandType[2];
	AnalysisValue operandValue[2];

	AnalysisVariableValue(AnalysisValueOp op, AnalysisValueType type1, AnalysisValue value1, AnalysisValueType type2, AnalysisValue value2)
		: op(op)
	{
		setOperand(0, type1, value1);
		setOperand(1, type2, value2);
	}

	AnalysisVariableValue(AnalysisValueType type, AnalysisValue value)
		: op(AnalysisValueOp::Assign)
	{
		setOperand(0, type, value);
		setUnknown(1);
	}

	AnalysisVariableValue() : AnalysisVariableValue(AnalysisValueType::Unknown, { .constant = 0 }) {}
	AnalysisVariableValue(i64 value) : AnalysisVariableValue(AnalysisValueType::Constant, { .constant = value }) {}
	AnalysisVariableValue(AnalysisPointer value) : AnalysisVariableValue(AnalysisValueType::Pointer, { .ptr = value }) {}
	AnalysisVariableValue(AnalysisVariableRef value) : AnalysisVariableValue(AnalysisValueType::Deref, { .var = value }) {}
	AnalysisVariableValue(AnalysisValueWithType val) : AnalysisVariableValue(val.type, val.value) {}

	void setOperand(int index, AnalysisValueType type, AnalysisValue value)
	{
		operandType[index] = type;
		operandValue[index] = value;
	}

	void setUnknown(int index) { setOperand(index, AnalysisValueType::Unknown, { .constant = 0 }); }
	void setConstant(int index, i64 value) { setOperand(index, AnalysisValueType::Constant, { .constant = value }); }
	void setPointer(int index, AnalysisPointer value) { setOperand(index, AnalysisValueType::Pointer, { .ptr = value }); }
	void setPointer(int index, int addressSpace, int offset) { setPointer(index, { addressSpace, offset }); }
	void setVariable(int index, AnalysisVariableRef value) { setOperand(index, AnalysisValueType::Deref, { .var = value }); }
	void setVariable(int index, int var, int version) { setVariable(index, { var, version }); }

	bool isUnknown() const { return op == AnalysisValueOp::Assign && operandType[0] == AnalysisValueType::Unknown; }

	AnalysisValueWithType getOperand(int index) { return{ operandType[index], operandValue[index] }; }
};

struct AnalysisVariableHistory
{
	SmallVector<AnalysisVariableValue, 1> entries;

	AnalysisVariableHistory() { entries.emplace_back(); }
};

struct AnalysisVariables
{
	enum StandardAddressSpaces
	{
		AS_Unknown,
		AS_Global, // offset = rva
		AS_Stack, // offset 0 is retaddr
		AS_Thread, // gs:[offset]

		AS_Count
	};

	enum StandardVariables
	{
		V_rax,
		V_rcx,
		V_rdx,
		V_rbx,
		V_rsp,
		V_rbp,
		V_rsi,
		V_rdi,
		V_r8,
		V_r9,
		V_r10,
		V_r11,
		V_r12,
		V_r13,
		V_r14,
		V_r15,
		V_xmm0,
		V_xmm1,
		V_xmm2,
		V_xmm3,
		V_xmm4,
		V_xmm5,
		V_xmm6,
		V_xmm7,
		V_xmm8,
		V_xmm9,
		V_xmm10,
		V_xmm11,
		V_xmm12,
		V_xmm13,
		V_xmm14,
		V_xmm15,

		V_Count
	};

	std::vector<SimpleRangeMap<int, int>> addressSpaces; // for each address space: key = offset, value = variable index
	std::vector<AnalysisVariableHistory> variables; // history
};

// basic blocks are sorted topological order (aka reversed post-order): a block is always ordered before it's (non-loop) successors
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

		simplifyGraph(mapping);
		calculateImmediateDominators();
		calculateDominanceFrontiers();
		emulate();

		// TODO: emulate all instructions, do constant propagation and detect loads/stores/global refs/calls
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
		assert(assignedBlock.fblocks.empty());
		assignedBlock.fblocks.push_back(&fblock);
		assignedBlock.successors = std::move(succTopoIndices);
	}

	void simplifyGraph(std::vector<int>& mapping)
	{
		assert(mapping.size() == mBlocks.size() && mapping[0] == 0);
		// collapse basic blocks with single edge between them
		// collapsible blocks are always adjacent in topological order
		// TODO: collapse nop-only blocks: they have only 1 successor, can be killed with predecessors repointed to successor...
		int prevIndex = 0;
		for (int i = 1; i < mBlocks.size(); ++i)
		{
			auto& prev = mBlocks[prevIndex];
			auto& curr = mBlocks[i];
			assert(curr.fblocks.size() == 1);
			if (curr.predecessors.size() == 1 && curr.predecessors[0] == i - 1 && prev.successors.size() == 1 && prev.successors[0] == i)
			{
				// collapse curr with prev
				mapping[i] = prevIndex;
				prev.fblocks.push_back(curr.fblocks[0]);
				prev.successors = std::move(curr.successors);
			}
			else
			{
				// preserve block as is, compacting if needed
				mapping[i] = ++prevIndex;
				if (prevIndex != i)
					mBlocks[prevIndex] = std::move(curr);
			}
		}
		mBlocks.resize(++prevIndex);
		// now that we've remapped all blocks, update edge indices
		for (auto& b : mBlocks)
		{
			for (auto& e : b.successors)
				e = mapping[e];
			for (auto& e : b.predecessors)
				e = mapping[e];
		}
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

	void emulate()
	{
		// initial setup
		mVariables.addressSpaces.resize(AnalysisVariables::AS_Count);
		mVariables.variables.resize(AnalysisVariables::V_Count);
		mVariables.variables[AnalysisVariables::V_rsp].entries[0].setPointer(0, AnalysisVariables::AS_Stack, 0);
		for (int i = 0; i < mBlocks.size(); ++i)
		{
			auto& block = mBlocks[i];
			for (auto& f : block.fblocks)
			{
				for (auto& isn : f->instructions)
				{
					switch (isn.mnem)
					{
					case X86_INS_MOV:
						emulateMov(i, isn);
						break;
					case X86_INS_PUSH:
						emulatePush(i, isn);
						break;
					case X86_INS_LEA:
						emulateLea(i, isn);
						break;
					case X86_INS_ADD:
						emulateAdd(i, isn);
						break;
					case X86_INS_SUB:
						emulateSub(i, isn);
						break;
					case X86_INS_XOR:
						emulateXor(i, isn);
						break;
					case X86_INS_BTC:
						emulateBtc(i, isn);
						break;
					case X86_INS_NOP:
					case X86_INS_JMP:
						break;
					default:
						__debugbreak();
					}
				}
			}
		}
	}

	void emulateLea(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2 && isn.ops[0].type == OperandType::Reg && (isn.ops[1].type == OperandType::Mem || isn.ops[1].type == OperandType::MemRVA));
		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8);
		auto value = calculatePointerValue(iBlock, isn, isn.ops[1].type == OperandType::MemRVA);
		auto destIndex = variableIndexForOperand(iBlock, isn, isn.ops[0]);
		setVariable(iBlock, destIndex, isn.rva, value);
	}

	void emulateMov(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8); // TODO: mov reg,xxx with non-8 size
		auto value = calculateOperandValue(iBlock, isn, isn.ops[1]);
		auto destIndex = variableIndexForOperand(iBlock, isn, isn.ops[0]);
		setVariable(iBlock, destIndex, isn.rva, value);
	}

	void emulateAdd(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
		{
			// add x, x ==> x *= 2
			__debugbreak();
		}
		else
		{
			assert(isn.ops[0].size == 8 && isn.ops[1].size == 8); // TODO: sub reg,xxx with non-8 size
			auto value = derefSimple(calculateOperandValue(iBlock, isn, isn.ops[1]));
			auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
			assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
			auto modified = executeBinaryOp(derefSimple(src), AnalysisValueOp::Add, value);
			setVariable(iBlock, src.value.var.index, isn.rva, std::move(modified));
		}
	}

	void emulateSub(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
		{
			// sub x, x ==> x = 0
			assert(isn.ops[0].size == isn.ops[1].size);
			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
			auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
			assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
			setVariable(iBlock, src.value.var.index, isn.rva, AnalysisValueWithType{ 0 });
		}
		else
		{
			assert(isn.ops[0].size == 8 && isn.ops[1].size == 8); // TODO: sub reg,xxx with non-8 size
			auto value = derefSimple(calculateOperandValue(iBlock, isn, isn.ops[1]));
			auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
			assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
			auto modified = executeBinaryOp(derefSimple(src), AnalysisValueOp::Sub, value);
			setVariable(iBlock, src.value.var.index, isn.rva, std::move(modified));
		}
	}

	void emulateXor(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
		{
			// xor x, x ==> x = 0
			assert(isn.ops[0].size == isn.ops[1].size);
			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
			auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
			assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
			setVariable(iBlock, src.value.var.index, isn.rva, AnalysisValueWithType{ 0 });
		}
		else
		{
			assert(isn.ops[0].size == 8 && isn.ops[1].size == 8); // TODO: xor reg,xxx with non-8 size
			auto value = derefSimple(calculateOperandValue(iBlock, isn, isn.ops[1]));
			auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
			assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
			auto modified = executeBinaryOp(derefSimple(src), AnalysisValueOp::Xor, value);
			setVariable(iBlock, src.value.var.index, isn.rva, std::move(modified));
		}
	}

	void emulatePush(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 1 && isn.ops[0].size == 8);
		// push x ==> sub rsp, 8 + mov [rsp], x
		auto rspVersion = getLiveVariableVersion(iBlock, AnalysisVariables::V_rsp);
		auto& rsp = mVariables.variables[AnalysisVariables::V_rsp].entries[rspVersion];
		assert(rsp.op == AnalysisValueOp::Assign && rsp.operandType[0] == AnalysisValueType::Pointer);
		auto rspVal = rsp.operandValue[0].ptr;
		assert(rspVal.addressSpace == AnalysisVariables::AS_Stack);
		rspVal.offset -= 8;
		setVariable(iBlock, AnalysisVariables::V_rsp, isn.rva, AnalysisVariableValue{ rspVal });

		auto value = calculateOperandValue(iBlock, isn, isn.ops[0]);
		auto stackVar = variableIndexForPointer(rspVal, isn.ops[0].size);

		setVariable(iBlock, stackVar, isn.rva, value);
	}

	void emulateBtc(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[1].type == OperandType::Imm); // TODO: handle version with register?..
		assert(isn.ops[1].size == 1);
		// btc x, imm ==> xor x, (1 << imm)
		auto src = calculateOperandValue(iBlock, isn, isn.ops[0]);
		assert(src.type == AnalysisValueType::Deref); // op can only be reg or mem => resolves to variable
		auto modified = executeBinaryOp(derefSimple(src), AnalysisValueOp::Xor, { 1ll << isn.imm });
		setVariable(iBlock, src.value.var.index, isn.rva, std::move(modified));
	}

	AnalysisVariableValue executeBinaryOp(AnalysisValueWithType lhs, AnalysisValueOp op, AnalysisValueWithType rhs)
	{
		if (lhs.type == AnalysisValueType::Constant && rhs.type == AnalysisValueType::Constant)
		{
			// c1 op c2
			switch (op)
			{
			case AnalysisValueOp::Add:
				return{ lhs.value.constant + rhs.value.constant };
			case AnalysisValueOp::Sub:
				return{ lhs.value.constant - rhs.value.constant };
			case AnalysisValueOp::Xor:
				return{ lhs.value.constant ^ rhs.value.constant };
			default:
				__debugbreak();
				return{};
			}
		}
		else if (lhs.type == AnalysisValueType::Constant)
		{
			// c1 op v
			auto v = derefValue(rhs);
			switch (op)
			{
			case AnalysisValueOp::Add:
				if (v.op == AnalysisValueOp::Add)
				{
					// c1 + (x + y)
					if (v.operandType[0] == AnalysisValueType::Constant) // c1 + (c2 + x) ==> (c1 + c2) + x
						return{ AnalysisValueOp::Add, AnalysisValueType::Constant, { lhs.value.constant + v.operandValue[0].constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // c1 + (x + c2) ==> x + (c1 + c2)
						return{ AnalysisValueOp::Add, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { lhs.value.constant + v.operandValue[1].constant } };
				}
				else if (v.op == AnalysisValueOp::Sub)
				{
					// c1 + (x - y)
					if (v.operandType[0] == AnalysisValueType::Constant) // c1 + (c2 - x) ==> (c1 + c2) - x
						return{ AnalysisValueOp::Sub, AnalysisValueType::Constant, { lhs.value.constant + v.operandValue[0].constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // c1 + (x - c2) ==> x + (c1 - c2)
						return{ AnalysisValueOp::Add, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { lhs.value.constant - v.operandValue[1].constant } };
				}
				else if (v.op == AnalysisValueOp::Assign && v.operandType[0] == AnalysisValueType::Pointer)
				{
					// c1 + &[x + c2] ==> &[x + (c1 + c2)]
					return{ AnalysisPointer{ v.operandValue[0].ptr.addressSpace, static_cast<int>(v.operandValue[0].ptr.offset + lhs.value.constant) }};
				}
				break;
			case AnalysisValueOp::Sub:
				if (v.op == AnalysisValueOp::Add)
				{
					// c1 - (x + y)
					if (v.operandType[0] == AnalysisValueType::Constant) // c1 - (c2 + x) ==> (c1 - c2) + x
						return{ AnalysisValueOp::Add, AnalysisValueType::Constant, { lhs.value.constant - v.operandValue[0].constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // c1 - (x + c2) ==> (c1 - c2) - x
						return{ AnalysisValueOp::Sub, AnalysisValueType::Constant, { lhs.value.constant - v.operandValue[1].constant }, v.operandType[0], v.operandValue[0] };
				}
				else if (v.op == AnalysisValueOp::Sub)
				{
					// c1 - (x - y)
					if (v.operandType[0] == AnalysisValueType::Constant) // c1 - (c2 - x) ==> (c1 - c2) + x
						return{ AnalysisValueOp::Add, AnalysisValueType::Constant, { lhs.value.constant - v.operandValue[0].constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // c1 - (x - c2) ==> (c1 + c2) - x
						return{ AnalysisValueOp::Sub, AnalysisValueType::Constant, { lhs.value.constant + v.operandValue[1].constant }, v.operandType[0], v.operandValue[0] };
				}
				break;
			case AnalysisValueOp::Xor:
				if (v.op == AnalysisValueOp::Xor)
				{
					// c1 ^ (x ^ y)
					if (v.operandType[0] == AnalysisValueType::Constant) // c1 ^ (c2 ^ x) ==> (c1 ^ c2) ^ x
						return{ AnalysisValueOp::Xor, AnalysisValueType::Constant, { lhs.value.constant ^ v.operandValue[0].constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // c1 ^ (x ^ c2) ==> (c1 ^ c2) ^ x
						return{ AnalysisValueOp::Xor, AnalysisValueType::Constant, { lhs.value.constant ^ v.operandValue[1].constant }, v.operandType[0], v.operandValue[0] };
				}
				break;
			}
		}
		else if (rhs.type == AnalysisValueType::Constant)
		{
			// v op c2
			auto v = derefValue(lhs);
			switch (op)
			{
			case AnalysisValueOp::Add:
				if (v.op == AnalysisValueOp::Add)
				{
					// (x + y) + c2
					if (v.operandType[0] == AnalysisValueType::Constant) // (c1 + x) + c2 ==> (c1 + c2) + x
						return{ AnalysisValueOp::Add, AnalysisValueType::Constant, { v.operandValue[0].constant + rhs.value.constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // (x + c1) + c2 ==> x + (c1 + c2)
						return{ AnalysisValueOp::Add, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { v.operandValue[1].constant + rhs.value.constant } };
				}
				else if (v.op == AnalysisValueOp::Sub)
				{
					// (x - y) + c2
					if (v.operandType[0] == AnalysisValueType::Constant) // (c1 - x) + c2 ==> (c1 + c2) - x
						return{ AnalysisValueOp::Sub, AnalysisValueType::Constant, { v.operandValue[0].constant + rhs.value.constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // (x - c1) + c2 ==> x + (c2 - c1)
						return{ AnalysisValueOp::Add, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { rhs.value.constant - v.operandValue[1].constant } };
				}
				else if (v.op == AnalysisValueOp::Assign && v.operandType[0] == AnalysisValueType::Pointer)
				{
					// &[x + c1] + c2 ==> &[x + (c1 + c2)]
					return{ AnalysisPointer{ v.operandValue[0].ptr.addressSpace, static_cast<int>(v.operandValue[0].ptr.offset + rhs.value.constant) } };
				}
				break;
			case AnalysisValueOp::Sub:
				if (v.op == AnalysisValueOp::Add)
				{
					// (x + y) - c2
					if (v.operandType[0] == AnalysisValueType::Constant) // (c1 + x) - c2 ==> (c1 - c2) + x
						return{ AnalysisValueOp::Add, AnalysisValueType::Constant, { v.operandValue[0].constant - rhs.value.constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // (x + c1) - c2 ==> x + (c1 - c2)
						return{ AnalysisValueOp::Add, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { v.operandValue[1].constant - rhs.value.constant } };
				}
				else if (v.op == AnalysisValueOp::Sub)
				{
					// (x - y) - c2
					if (v.operandType[0] == AnalysisValueType::Constant) // (c1 - x) - c2 ==> (c1 - c2) - x
						return{ AnalysisValueOp::Sub, AnalysisValueType::Constant, { v.operandValue[0].constant - rhs.value.constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // (x - c1) - c2 ==> x - (c1 + c2)
						return{ AnalysisValueOp::Sub, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { v.operandValue[1].constant + rhs.value.constant } };
				}
				else if (v.op == AnalysisValueOp::Assign && v.operandType[0] == AnalysisValueType::Pointer)
				{
					// &[x + c1] - c2 ==> &[x + (c1 - c2)]
					return{ AnalysisPointer{ v.operandValue[0].ptr.addressSpace, static_cast<int>(v.operandValue[0].ptr.offset - rhs.value.constant) } };
				}
				break;
			case AnalysisValueOp::Xor:
				if (v.op == AnalysisValueOp::Xor)
				{
					// (x ^ y) ^ c2
					if (v.operandType[0] == AnalysisValueType::Constant) // (c1 ^ x) ^ c2 ==> (c1 ^ c2) ^ x
						return{ AnalysisValueOp::Xor, AnalysisValueType::Constant, { v.operandValue[0].constant ^ rhs.value.constant }, v.operandType[1], v.operandValue[1] };
					if (v.operandType[1] == AnalysisValueType::Constant) // (x ^ c1) ^ c2 ==> x ^ (c1 ^ c2)
						return{ AnalysisValueOp::Xor, v.operandType[0], v.operandValue[0], AnalysisValueType::Constant, { v.operandValue[1].constant ^ rhs.value.constant } };
				}
				break;
			}
		}
		// no constant propagation possible
		return{ op, lhs.type, lhs.value, rhs.type, rhs.value };
	}

	AnalysisValueWithType calculateOperandValue(int iBlock, const Instruction& isn, const Operand& operand)
	{
		switch (operand.type)
		{
		case OperandType::Invalid:
			return{};
		case OperandType::Imm:
			return{ isn.imm };
		case OperandType::ImmRVA:
			return{ AnalysisPointer{ AnalysisVariables::AS_Global, static_cast<i32>(isn.imm) } };
		default:
			return{ variableRefForOperand(iBlock, isn, operand) };
		}
	}

	AnalysisVariableRef variableRefForOperand(int iBlock, const Instruction& isn, const Operand& operand)
	{
		auto index = variableIndexForOperand(iBlock, isn, operand);
		auto version = getLiveVariableVersion(iBlock, index);
		return{ index, version };
	}

	int variableIndexForOperand(int iBlock, const Instruction& isn, const Operand& operand)
	{
		if (operand.type == OperandType::Reg)
		{
			return variableIndexForRegister(operand.reg, operand.size);
		}
		else
		{
			assert(operand.type == OperandType::Mem || operand.type == OperandType::MemRVA);
			auto addr = calculatePointerValue(iBlock, isn, operand.type == OperandType::MemRVA);
			assert(addr.type == AnalysisValueType::Pointer);
			return variableIndexForPointer(addr.value.ptr, operand.size);
		}
	}

	int variableIndexForRegister(x86_reg reg, int opsize)
	{
		switch (reg)
		{
		case X86_REG_EAX:
		case X86_REG_RAX:
			assert(opsize >= 4);
			return AnalysisVariables::V_rax;
		case X86_REG_ECX:
		case X86_REG_RCX:
			assert(opsize >= 4);
			return AnalysisVariables::V_rcx;
		case X86_REG_EDX:
		case X86_REG_RDX:
			assert(opsize >= 4);
			return AnalysisVariables::V_rdx;
		case X86_REG_EBX:
		case X86_REG_RBX:
			assert(opsize >= 4);
			return AnalysisVariables::V_rbx;
		//case X86_REG_ESP:
		case X86_REG_RSP:
			assert(opsize == 8);
			return AnalysisVariables::V_rsp;
		case X86_REG_EBP:
		case X86_REG_RBP:
			assert(opsize >= 4);
			return AnalysisVariables::V_rbp;
		case X86_REG_ESI:
		case X86_REG_RSI:
			assert(opsize >= 4);
			return AnalysisVariables::V_rsi;
		case X86_REG_EDI:
		case X86_REG_RDI:
			assert(opsize >= 4);
			return AnalysisVariables::V_rdi;
		case X86_REG_R9D:
		case X86_REG_R9:
			assert(opsize >= 4);
			return AnalysisVariables::V_r9;
		case X86_REG_R10D:
		case X86_REG_R10:
			assert(opsize >= 4);
			return AnalysisVariables::V_r10;
		case X86_REG_R11D:
		case X86_REG_R11:
			assert(opsize >= 4);
			return AnalysisVariables::V_r11;
		case X86_REG_R12D:
		case X86_REG_R12:
			assert(opsize >= 4);
			return AnalysisVariables::V_r12;
		case X86_REG_R13D:
		case X86_REG_R13:
			assert(opsize >= 4);
			return AnalysisVariables::V_r13;
		case X86_REG_R14D:
		case X86_REG_R14:
			assert(opsize >= 4);
			return AnalysisVariables::V_r14;
		case X86_REG_R15D:
		case X86_REG_R15:
			assert(opsize >= 4);
			return AnalysisVariables::V_r15;
		default:
			__debugbreak();
			return -1;
		}
	}

	AnalysisValueWithType calculatePointerValue(int iBlock, const Instruction& isn, bool rvaBase)
	{
		auto res = calculatePointerValueBase(iBlock, isn, rvaBase);
		auto off = calculatePointerValueOffset(iBlock, isn);
		switch (res.type)
		{
		case AnalysisValueType::Constant:
			res.value.constant += off;
			return res;
		case AnalysisValueType::Pointer:
			res.value.ptr.offset += off;
			return res;
		default:
			return{};
		}
	}

	AnalysisValueWithType calculatePointerValueBase(int iBlock, const Instruction& isn, bool rvaBase)
	{
		if (rvaBase)
		{
			assert(isn.mem.segment == X86_REG_INVALID);
			return{ AnalysisPointer{ AnalysisVariables::AS_Global } };
		}
		else if (isn.mem.segment == X86_REG_INVALID)
		{
			assert(isn.mem.base != X86_REG_INVALID);
			auto index = variableIndexForRegister(isn.mem.base, 8);
			auto version = getLiveVariableVersion(iBlock, index);
			auto& var = variableValue({ index, version });
			return var.op == AnalysisValueOp::Assign ? var.getOperand(0) : AnalysisValueWithType{};
		}
		else
		{
			__debugbreak(); // TODO
			return{};
		}
	}

	i32 calculatePointerValueOffset(int iBlock, const Instruction& isn)
	{
		auto offset = isn.mem.disp;
		if (isn.mem.index != X86_REG_INVALID && isn.mem.scale != 0)
		{
			auto index = variableIndexForRegister(isn.mem.index, 8);
			auto version = getLiveVariableVersion(iBlock, index);
			auto& var = variableValue({ index, version });
			if (var.op == AnalysisValueOp::Assign && var.operandType[0] == AnalysisValueType::Constant)
				offset += var.operandValue[0].constant;
		}
		return offset;
	}

	int variableIndexForPointer(AnalysisPointer ptr, int size)
	{
		auto& space = mVariables.addressSpaces[ptr.addressSpace];
		auto next = space.findNext(ptr.offset);
		auto it = space.getPrevIfContains(next, ptr.offset);
		if (it == space.end())
		{
			int idx = mVariables.variables.size();
			mVariables.variables.emplace_back();
			space.insert({ ptr.offset, ptr.offset + size, idx });
			return idx;
		}
		else
		{
			ensure(it->begin == ptr.offset && it->end == ptr.offset + size);
			return it->value;
		}
	}

	int getLiveVariableVersion(int iBlock, int iVar)
	{
		auto& var = mVariables.variables[iVar];
		for (int iVersion = var.entries.size() - 1; iVersion >= 0; --iVersion)
		{
			auto liveness = calculateVariableLiveness(iBlock, var.entries[iVersion]);
			if (liveness == Liveness::Reachable)
				return iVersion;
			if (liveness == Liveness::Partial)
				break;
		}
		// TODO: create new 'unknown' version?..
		__debugbreak();
		return -1;
	}

	enum class Liveness { Unreachable, Reachable, Partial };
	Liveness calculateVariableLiveness(int iBlock, const AnalysisVariableValue& var)
	{
		if (var.blockIndex == iBlock)
			return Liveness::Reachable;
		auto idom = mBlocks[iBlock].immediateDominator;
		if (var.blockIndex > idom)
			return std::ranges::contains(mBlocks[var.blockIndex].dominanceFrontier, iBlock) ? Liveness::Partial : Liveness::Unreachable;
		else if (var.blockIndex == idom)
			return Liveness::Reachable;
		else
			return calculateVariableLiveness(idom, var);
	}

	void setVariable(int iBlock, int iVar, rva_t rva, AnalysisValueWithType val) { setVariable(iBlock, iVar, rva, derefValue(val)); }
	void setVariable(int iBlock, int iVar, rva_t rva, AnalysisVariableValue&& value)
	{
		if (value.operandType[0] == AnalysisValueType::Deref)
			++variableValue(value.operandValue[0].var).numRefs;
		if (value.operandType[1] == AnalysisValueType::Deref)
			++variableValue(value.operandValue[1].var).numRefs;

		auto& var = mVariables.variables[iVar];
		if (var.entries.back().blockIndex == iBlock && var.entries.back().numRefs == 0)
			var.entries.pop_back();
		value.assignment = rva;
		value.blockIndex = iBlock;
		var.entries.push_back(std::move(value));
	}

	AnalysisVariableValue& variableValue(AnalysisVariableRef ref) { return mVariables.variables[ref.index].entries[ref.version]; }

	AnalysisValueWithType derefSimple(AnalysisValueWithType val)
	{
		if (val.type == AnalysisValueType::Deref)
		{
			auto& value = variableValue(val.value.var);
			if (value.op == AnalysisValueOp::Assign && value.operandType[0] != AnalysisValueType::Unknown)
				return value.getOperand(0);
		}
		return val;
	}

	AnalysisVariableValue derefValue(AnalysisValueWithType ref)
	{
		if (ref.type == AnalysisValueType::Deref)
		{
			auto& value = variableValue(ref.value.var);
			if (!value.isUnknown())
				return value;
		}
		return{ ref };
	}

private:
	std::vector<BasicBlock> mBlocks; // sorted in topological (reverse-post) order
	AnalysisVariables mVariables;
};
