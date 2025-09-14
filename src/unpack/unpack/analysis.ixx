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

enum class AnalysisValueOp : u8
{
	Assign, // = op1
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
					case X86_ISN_LEA:
						emulateLea(i, isn);
						break;
					default:
						__debugbreak();
					}
				}
			}
		}
	}

	void emulateMov(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2);
		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8); // TODO: mov reg,xxx with non-8 size
		AnalysisVariableValue value = derefOperand(iBlock, isn, isn.ops[1], true);

		auto destIndex = resolveVariable(isn, isn.ops[0]);
		setVariable(iBlock, destIndex, isn.rva, std::move(value));
	}

	void emulatePush(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 1 && isn.ops[0].size == 8);
		auto rspVersion = getLiveVariableVersion(iBlock, AnalysisVariables::V_rsp);
		auto& rsp = mVariables.variables[AnalysisVariables::V_rsp].entries[rspVersion];
		assert(rsp.op == AnalysisValueOp::Assign && rsp.operandType[0] == AnalysisValueType::Pointer);
		auto rspVal = rsp.operandValue[0].ptr;
		assert(rspVal.addressSpace == AnalysisVariables::AS_Stack);
		rspVal.offset -= 8;
		setVariable(iBlock, AnalysisVariables::V_rsp, isn.rva, { rspVal });

		AnalysisVariableValue value = derefOperand(iBlock, isn, isn.ops[0], true);
		auto stackVar = resolvePointerVariable(rspVal, isn.ops[0].size);

		setVariable(iBlock, stackVar, isn.rva, std::move(value));
	}

	void emulateLea(int iBlock, const Instruction& isn)
	{
		assert(isn.opcount == 2 && isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Mem);
		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8);
	}

	AnalysisVariableValue derefOperand(int iBlock, const Instruction& isn, const Operand& operand, bool allowExpressions)
	{
		if (operand.type == OperandType::Imm)
		{
			return{ isn.imm };
		}
		else
		{
			auto srcIndex = resolveVariable(isn, operand);
			auto srcVersion = getLiveVariableVersion(iBlock, srcIndex);
			auto& src = mVariables.variables[srcIndex].entries[srcVersion];
			if (src.isUnknown() || src.op != AnalysisValueOp::Assign && !allowExpressions)
			{
				++src.numRefs;
				return{ AnalysisVariableRef{ srcIndex, srcVersion } };
			}
			else
			{
				if (src.operandType[0] == AnalysisValueType::Deref)
					++mVariables.variables[src.operandValue[0].var.index].entries[src.operandValue[0].var.version].numRefs;
				if (src.operandType[1] == AnalysisValueType::Deref)
					++mVariables.variables[src.operandValue[1].var.index].entries[src.operandValue[1].var.version].numRefs;
				return src;
			}
		}
	}

	int resolveVariable(const Instruction& isn, const Operand& operand)
	{
		switch (operand.type)
		{
		case OperandType::Reg:
			switch (operand.reg)
			{
			case X86_REG_RAX:
				assert(operand.size == 8);
				return AnalysisVariables::V_rax;
			case X86_REG_RCX:
				assert(operand.size == 8);
				return AnalysisVariables::V_rcx;
			case X86_REG_RDX:
				assert(operand.size == 8);
				return AnalysisVariables::V_rdx;
			case X86_REG_RBX:
				assert(operand.size == 8);
				return AnalysisVariables::V_rbx;
			case X86_REG_RSP:
				assert(operand.size == 8);
				return AnalysisVariables::V_rsp;
			case X86_REG_RBP:
				assert(operand.size == 8);
				return AnalysisVariables::V_rbp;
			case X86_REG_RSI:
				assert(operand.size == 8);
				return AnalysisVariables::V_rsi;
			case X86_REG_RDI:
				assert(operand.size == 8);
				return AnalysisVariables::V_rdi;
			default:
				__debugbreak();
				return -1;
			}
			break;
		default:
			__debugbreak();
			return -1;
		}
	}

	int resolvePointerVariable(AnalysisPointer ptr, int size)
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
			auto& version = var.entries[iVersion];
			if (version.blockIndex == iBlock)
				return iVersion;
		checkDom:
			auto idom = mBlocks[iBlock].immediateDominator;
			if (version.blockIndex > idom)
			{
				if (std::ranges::contains(mBlocks[version.blockIndex].dominanceFrontier, iBlock))
					break; // phi
				continue; // this version is on a parallel branch, continue looking...
			}
			if (version.blockIndex == idom)
				return iVersion; // ok
			iBlock = idom;
			goto checkDom;
		}
		// TODO: create new 'unknown' version?..
		__debugbreak();
		return -1;
	}

	void setVariable(int iBlock, int iVar, rva_t rva, AnalysisVariableValue&& value)
	{
		auto& var = mVariables.variables[iVar];
		if (var.entries.back().blockIndex == iBlock && var.entries.back().numRefs == 0)
			var.entries.pop_back();
		value.assignment = rva;
		value.blockIndex = iBlock;
		var.entries.push_back(std::move(value));
	}

private:
	std::vector<BasicBlock> mBlocks; // sorted in topological (reverse-post) order
	AnalysisVariables mVariables;
};
