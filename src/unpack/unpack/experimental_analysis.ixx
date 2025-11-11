//module;
//
//#include <common/bitfield_ops.h>
//#include <common/win_headers.h>
//#include <capstone/capstone.h>
//#include <cassert>
//
//export module unpack.experimental_analysis;
//
//import std;
//import common;
//import unpack.pe_binary;
//import unpack.instruction;
//import unpack.function;
//
//// an uninterrupted sequence of instructions; each basic block has only one entry point
//// topologically sorted (aka reverse post-order), so:
//// - all non-loop predecessors are ordered before a given block
//// - two disjoint instruction ranges that can conceptually be combined into a single basic block have successive indices
//export struct AnalysisBlock
//{
//	const FunctionBlock* fblock;
//	SmallVector<int, 2> successors;
//	SmallVector<int, 2> predecessors;
//	SmallVector<int, 2> dominanceFrontier;
//	int immediateDominator = -1;
//};
//
//struct AnalysisPointer
//{
//	int addressSpace;
//	int offset;
//};
//AnalysisPointer operator+(AnalysisPointer l, i32 r) { return{ l.addressSpace, l.offset + r }; }
//AnalysisPointer& operator+=(AnalysisPointer& l, i32 r) { l.offset += r; return l; }
//AnalysisPointer operator-(AnalysisPointer l, i32 r) { return{ l.addressSpace, l.offset - r }; }
//AnalysisPointer& operator-=(AnalysisPointer& l, i32 r) { l.offset -= r; return l; }
//
//struct AnalysisExpressionRef
//{
//	size_t index;
//};
//
//union AnalysisValue
//{
//	i64 constant;
//	AnalysisPointer ptr;
//	AnalysisExpressionRef expr;
//};
//
//enum class AnalysisValueType : u8
//{
//	Unknown,
//	Constant,
//	Pointer,
//	Expression,
//};
//
//struct AnalysisValueWithType
//{
//	AnalysisValueType type;
//	AnalysisValue value;
//
//	AnalysisValueWithType() : type(AnalysisValueType::Unknown), value(0) {}
//	AnalysisValueWithType(i64 value) : type(AnalysisValueType::Constant), value(value) {}
//	AnalysisValueWithType(AnalysisPointer value) : type(AnalysisValueType::Pointer), value{ .ptr = value } {}
//	AnalysisValueWithType(AnalysisExpressionRef value) : type(AnalysisValueType::Expression), value{ .expr = value } {}
//	AnalysisValueWithType(AnalysisValueType type, AnalysisValue value) : type(type), value(value) {}
//};
//bool operator==(const AnalysisValueWithType& l, const AnalysisValueWithType& r) { return l.type == r.type && l.value.constant == r.value.constant; }
//
//template<> struct std::formatter<AnalysisValueWithType>
//{
//	constexpr auto parse(format_parse_context& ctx)
//	{
//		return ctx.begin();
//	}
//
//	auto format(const AnalysisValueWithType& obj, format_context& ctx) const
//	{
//		switch (obj.type)
//		{
//		case AnalysisValueType::Constant:
//			return format_to(ctx.out(), "0x{:X}", (u64)obj.value.constant);
//		case AnalysisValueType::Pointer:
//			if (obj.value.ptr.offset >= 0)
//				return format_to(ctx.out(), "[AS_{} + 0x{:X}]", obj.value.ptr.addressSpace, obj.value.ptr.offset);
//			else
//				return format_to(ctx.out(), "[AS_{} - 0x{:X}]", obj.value.ptr.addressSpace, -obj.value.ptr.offset);
//		case AnalysisValueType::Expression:
//			return format_to(ctx.out(), "${}", obj.value.expr.index);
//		default:
//			return format_to(ctx.out(), "???");
//		}
//	}
//};
//
//enum class AnalysisExpressionOp : u8
//{
//	Invalid,
//
//	// unary expressions
//	Deref, // = *op1
//	Neg, // = -op1
//	Not, // = ~op1
//	SignExtend, // = sign-extended op1
//	ZeroExtend, // = zero-extended op1
//	Call, // = op1(...)
//	LastUnary,
//
//	// binary expressions
//	Add, // = op1 + op2
//	MulLo, // = op1 * op2
//	Xor, // = op1 ^ op2
//	Or, // = op1 | op2
//	LastBinary,
//};
//
//// note: for commutative binary ops, if one of the operands is constant, it's always second one
//struct AnalysisExpression
//{
//	rva_t rva = 0;
//	int blockIndex = 0;
//	int size = 0; // byte width of the result (TODO: do we care here?..)
//	AnalysisExpressionOp op = AnalysisExpressionOp::Invalid;
//	AnalysisValueType operandType[2] = {};
//	AnalysisValue operandValue[2] = {};
//
//	AnalysisExpression() = default;
//
//	// binary op
//	AnalysisExpression(int size, AnalysisValueWithType lhs, AnalysisExpressionOp op, AnalysisValueWithType rhs)
//		: size(size), op(op)
//	{
//		setOperand(0, lhs);
//		setOperand(1, rhs);
//	}
//
//	// unary op
//	AnalysisExpression(int size, AnalysisExpressionOp op, AnalysisValueWithType value) : AnalysisExpression(size, value, op, {}) {}
//
//	AnalysisValueWithType getOperand(int index) const { return{ operandType[index], operandValue[index] }; }
//	void setOperand(int index, AnalysisValueWithType value)
//	{
//		operandType[index] = value.type;
//		operandValue[index] = value.value;
//	}
//};
//
//template<> struct std::formatter<AnalysisExpression>
//{
//	constexpr auto parse(format_parse_context& ctx)
//	{
//		return ctx.begin();
//	}
//
//	auto format(const AnalysisExpression& obj, format_context& ctx) const
//	{
//		switch (obj.op)
//		{
//		case AnalysisExpressionOp::Deref: return format_to(ctx.out(), "*{}", obj.getOperand(0));
//		case AnalysisExpressionOp::Neg: return format_to(ctx.out(), "-{}", obj.getOperand(0));
//		case AnalysisExpressionOp::Not: return format_to(ctx.out(), "~{}", obj.getOperand(0));
//		case AnalysisExpressionOp::SignExtend: return format_to(ctx.out(), "sx {}", obj.getOperand(0));
//		case AnalysisExpressionOp::ZeroExtend: return format_to(ctx.out(), "zx {}", obj.getOperand(0));
//		case AnalysisExpressionOp::Call: return format_to(ctx.out(), "{}(...)", obj.getOperand(0));
//		case AnalysisExpressionOp::Add: return format_to(ctx.out(), "{} + {}", obj.getOperand(0), obj.getOperand(1));
//		case AnalysisExpressionOp::MulLo: return format_to(ctx.out(), "{} * {}", obj.getOperand(0), obj.getOperand(1));
//		case AnalysisExpressionOp::Xor: return format_to(ctx.out(), "{} ^ {}", obj.getOperand(0), obj.getOperand(1));
//		case AnalysisExpressionOp::Or: return format_to(ctx.out(), "{} | {}", obj.getOperand(0), obj.getOperand(1));
//		default: return format_to(ctx.out(), "??? {}", (int)obj.op);
//		}
//	}
//};
//
//// known memory state
//struct AnalysisState
//{
//	std::vector<SimpleRangeMap<int, AnalysisValueWithType>> addressSpaces; // for each address space: key = offset, value = variable state
//
//	enum StandardAddressSpaces
//	{
//		AS_Register, // offset depends on register id
//		AS_Global, // offset = rva
//		AS_Stack, // offset 0 is retaddr
//		AS_TEB, // gs:[offset], contains TEB
//		AS_PEB,
//		AS_LoaderData, // in PEB
//		AS_LoaderDataEntry,
//
//		AS_Count
//	};
//
//	static AnalysisState buildEntryState()
//	{
//		AnalysisState res;
//		res.addressSpaces.resize(AS_Count);
//		auto [rspStart, rspEnd] = Register::toRange(X86_REG_RSP);
//		res.addressSpaces[AS_Register].insert({ rspStart, rspEnd, AnalysisPointer{ AS_Stack }});
//		res.addressSpaces[AS_TEB].insert({ 0x30, 0x38, AnalysisPointer{ AS_TEB } }); // NtTib.Self
//		res.addressSpaces[AS_TEB].insert({ 0x60, 0x68, AnalysisPointer{ AS_PEB } });
//		res.addressSpaces[AS_PEB].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderData } });
//		res.addressSpaces[AS_LoaderData].insert({ 0x10, 0x18, AnalysisPointer{ AS_LoaderDataEntry } }); // InLoadOrderModuleList
//		res.addressSpaces[AS_LoaderData].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderDataEntry } });
//		res.addressSpaces[AS_LoaderData].insert({ 0x20, 0x28, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } }); // InMemoryOrderModuleList
//		res.addressSpaces[AS_LoaderData].insert({ 0x28, 0x30, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } });
//		res.addressSpaces[AS_LoaderData].insert({ 0x30, 0x38, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } }); // InInitializationOrderModuleList
//		res.addressSpaces[AS_LoaderData].insert({ 0x38, 0x40, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } });
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x0, 0x8, AnalysisPointer{ AS_LoaderDataEntry } }); // InLoadOrderLinks
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x8, 0x10, AnalysisPointer{ AS_LoaderDataEntry } });
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x10, 0x18, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } }); // InMemoryOrderLinks
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x18, 0x20, AnalysisPointer{ AS_LoaderDataEntry, 0x10 } });
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x20, 0x28, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } }); // InInitializationOrderLinks
//		res.addressSpaces[AS_LoaderDataEntry].insert({ 0x28, 0x30, AnalysisPointer{ AS_LoaderDataEntry, 0x20 } });
//		return res;
//	}
//
//	void merge(const AnalysisState& other)
//	{
//		// TODO: consider adding some phi expressions? not sure how useful that would be...
//		assert(addressSpaces.size() == other.addressSpaces.size());
//		for (int i = 0; i < addressSpaces.size(); ++i)
//		{
//			auto& dest = addressSpaces[i];
//			auto& src = other.addressSpaces[i];
//			auto iDest = dest.begin();
//			auto iSrc = src.begin();
//			while (iDest != dest.end())
//			{
//				while (iSrc != src.end() && iSrc->begin < iDest->begin)
//					++iSrc; // skip any entries that don't exist in merge destination
//				if (iSrc == src.end())
//					break; // no more entries to merge, anything left in destination is to be removed
//
//				if (iDest->begin == iSrc->begin && iDest->end == iSrc->end && iDest->value == iSrc->value)
//				{
//					// matching value, keep as is
//					++iDest;
//					++iSrc;
//					continue;
//				}
//
//				// some mismatch, remove everything up to the end of merged-in entry
//				auto mismatchEnd = iDest;
//				while (mismatchEnd != dest.end() && mismatchEnd->begin < iSrc->end)
//					++mismatchEnd;
//				iDest = dest.erase(iDest, mismatchEnd); // TODO: we can do better i guess...
//			}
//			dest.erase(iDest, dest.end()); // remove the rest
//		}
//	}
//};
//
////export struct AnalysisResult
////{
////	std::vector<AnalysisBlock> mBlocks; // sorted in topological (reverse-post) order
////	std::vector<AnalysisState> mExitStates;
////	std::vector<AnalysisExpression> mExpressions;
////};
//
//export class AnalyzedFunction
//{
//public:
//	AnalyzedFunction(const PEBinary& bin, const FunctionInfo& func, bool log = false) : mBin(bin), mLog(log)
//	{
//		// first build a 1:1 mapping of raw function blocks to basic blocks
//		std::vector<int> mapping(func.blocks().size());
//		mBlocks.resize(func.blocks().size());
//		int lastTopoIndex = mBlocks.size();
//		visitNewBlock(func, 0, lastTopoIndex, mapping);
//		assert(lastTopoIndex == 0);
//		assert(mapping[0] == 0);
//
//		// remap successor indices and determine predecessors
//		for (int i = 0; i < mBlocks.size(); ++i)
//		{
//			auto& b = mBlocks[i];
//			for (auto& succ : b.successors)
//			{
//				succ = mapping[succ];
//				mBlocks[succ].predecessors.push_back(i);
//			}
//			std::ranges::sort(b.successors);
//		}
//
//		calculateImmediateDominators();
//		calculateDominanceFrontiers();
//
//		// TODO: entry state should be customizable...
//		emulate(AnalysisState::buildEntryState());
//	}
//
//private:
//	void visitNewBlock(const FunctionInfo& func, int blockIndex, int& lastTopoIndex, std::vector<int>& mapping)
//	{
//		assert(mapping[blockIndex] == 0);
//		mapping[blockIndex] = -1; // mark as being visited
//		auto& fblock = func.blocks()[blockIndex];
//
//		// convert successor rvas to function block indices
//		// later we'll convert that to base block indices, after we place them all
//		SmallVector<int, 2> succTopoIndices(fblock.successors | std::ranges::views::transform([&](const FunctionEdge& edge) { return func.blocks().findIndex(edge.rva); }));
//
//		// now visit all successors that haven't been visited yet
//		for (auto succ : succTopoIndices | std::ranges::views::reverse)
//		{
//			if (mapping[succ] == 0)
//			{
//				visitNewBlock(func, succ, lastTopoIndex, mapping);
//			}
//		}
//
//		assert(lastTopoIndex > 0);
//		auto& assignedBlock = mBlocks[--lastTopoIndex];
//		mapping[blockIndex] = lastTopoIndex;
//		assert(!assignedBlock.fblock);
//		assignedBlock.fblock = &fblock;
//		assignedBlock.successors = std::move(succTopoIndices);
//	}
//
//	void calculateImmediateDominators()
//	{
//		// see http://www.hipersoft.rice.edu/grads/publications/dom14.pdf
//		mBlocks[0].immediateDominator = 0; // note: this is not great, but whatever...
//		bool needAnotherIteration = true;
//		while (needAnotherIteration)
//		{
//			needAnotherIteration = false;
//			for (int i = 1; i < mBlocks.size(); ++i)
//			{
//				auto& b = mBlocks[i];
//				int newIdom = b.predecessors[0];
//				for (int p : b.predecessors | std::ranges::views::drop(1))
//				{
//					if (mBlocks[p].immediateDominator >= 0)
//					{
//						newIdom = findCommonDominator(p, newIdom);
//					}
//				}
//				if (b.immediateDominator != newIdom)
//				{
//					b.immediateDominator = newIdom;
//					needAnotherIteration = true;
//				}
//			}
//		}
//	}
//
//	int findCommonDominator(int i1, int i2) const
//	{
//		while (i1 != i2)
//		{
//			while (i1 > i2)
//				i1 = mBlocks[i1].immediateDominator;
//			while (i2 > i1)
//				i2 = mBlocks[i2].immediateDominator;
//		}
//		return i1;
//	}
//
//	void calculateDominanceFrontiers()
//	{
//		for (int i = 0; i < mBlocks.size(); ++i)
//		{
//			auto& b = mBlocks[i];
//			for (auto p : b.predecessors)
//			{
//				while (p != b.immediateDominator)
//				{
//					auto& pred = mBlocks[p];
//					if (!pred.dominanceFrontier.empty() && pred.dominanceFrontier.back() == i)
//						break; // i was already added to the dominance frontier of p (and thus it's idom chain) on previous iterations
//					pred.dominanceFrontier.push_back(i);
//					p = pred.immediateDominator;
//				}
//			}
//		}
//	}
//
//	AnalysisState buildEntryState(int iBlock)
//	{
//		auto& block = mBlocks[iBlock];
//		assert(!block.predecessors.empty());
//		AnalysisState state = mExitStates[block.predecessors.front()]; // TODO: move if this is the last successor...
//		for (auto i : block.predecessors | std::ranges::views::drop(1))
//		{
//			if (i >= iBlock)
//				continue; // loop link
//			state.merge(mExitStates[i]);
//		}
//		return state;
//	}
//
//	void emulate(AnalysisState&& initialState)
//	{
//		// initial setup
//		mExitStates.resize(mBlocks.size());
//
//		emulateBlock(0, std::move(initialState));
//		for (int i = 1; i < mBlocks.size(); ++i)
//		{
//			emulateBlock(i, buildEntryState(i));
//		}
//	}
//
//	void emulateBlock(int iBlock, AnalysisState&& initialState)
//	{
//		log("> block #{}: 0x{:X}-0x{:X}, predecessors={}", iBlock, mBlocks[iBlock].fblock->begin, mBlocks[iBlock].fblock->end, mBlocks[iBlock].predecessors);
//		mCurrentBlockIndex = iBlock;
//		mExitStates[iBlock] = std::move(initialState);
//		for (auto& isn : mBlocks[iBlock].fblock->instructions)
//			emulateInstruction(isn);
//	}
//
//	void emulateInstruction(const Instruction& isn)
//	{
//		log(">> 0x{:X}: {}", isn.rva, InstructionPrinter(mBin, isn));
//		switch (isn.mnem)
//		{
//		case X86_INS_MOV: return emulateMov(isn);
//		case X86_INS_MOVABS: return emulateMov(isn); // mov reg, imm64
//		case X86_INS_MOVSXD: return emulateMovSX(isn);
//		case X86_INS_MOVZX: return emulateMovZX(isn);
//		case X86_INS_PUSH: return emulatePush(isn);
//		case X86_INS_LEA: return emulateLea(isn);
//		case X86_INS_ADD: return emulateAdd(isn);
//		case X86_INS_SUB: return emulateSub(isn);
//		case X86_INS_INC: return emulateInc(isn);
//		case X86_INS_IMUL: return emulateIMul(isn);
//		case X86_INS_XOR: return emulateXor(isn);
//		case X86_INS_OR: return emulateOr(isn);
//		case X86_INS_BTC: return emulateBtc(isn);
//
//		case X86_INS_CMP:
//		case X86_INS_TEST:
//			return; // no-op, unless we start caring about flags
//
//		case X86_INS_JO: case X86_INS_JNO:
//		case X86_INS_JS: case X86_INS_JNS:
//		case X86_INS_JE: case X86_INS_JNE:
//		case X86_INS_JB: case X86_INS_JAE:
//		case X86_INS_JP: case X86_INS_JNP:
//		case X86_INS_JBE: case X86_INS_JA:
//		case X86_INS_JL: case X86_INS_JGE:
//		case X86_INS_JLE: case X86_INS_JG:
//			return; // conditional jumps...
//
//		case X86_INS_CALL: return emulateCall(isn);
//		case X86_INS_INT: return emulateInt(isn);
//
//		case X86_INS_NOP:
//		case X86_INS_JMP:
//			break;
//
//		case X86_INS_MOVUPS: return emulateMov(isn); // TODO: treat as 4 floats instead?..
//		case X86_INS_MOVSD: return emulateMovSD(isn);
//
//		default:
//			__debugbreak();
//		}
//	}
//
//	void emulateLea(const Instruction& isn)
//	{
//		assert(isn.opcount == 2 && isn.ops[0].type == OperandType::Reg && (isn.ops[1].type == OperandType::Mem || isn.ops[1].type == OperandType::MemRVA));
//		assert(isn.ops[0].size == 8 && isn.ops[1].size == 8);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = operandAddress(isn, isn.ops[1]);
//		derefStore(dest, isn.ops[0].size, isn.rva, value);
//	}
//
//	void emulateMov(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size == isn.ops[1].size);
//		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
//			return; // mov x, x is a no-op
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = read(isn, isn.ops[1]);
//		derefStore(dest, isn.ops[0].size, isn.rva, value);
//	}
//
//	void emulateMovSX(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size > isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = read(isn, isn.ops[1]);
//		derefStore(dest, isn.ops[0].size, isn.rva, simplifySignExtend(isn.rva, isn.ops[0].size, value, isn.ops[1].size));
//	}
//
//	void emulateMovZX(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size > isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = read(isn, isn.ops[1]);
//		derefStore(dest, isn.ops[0].size, isn.rva, simplifyZeroExtend(isn.rva, isn.ops[0].size, value, isn.ops[1].size));
//	}
//
//	void emulateMovSD(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		if (isn.ops[0].type != OperandType::Reg)
//		{
//			// movsd mem, reg
//			assert(isn.ops[0].type == OperandType::Mem || isn.ops[0].type == OperandType::MemRVA);
//			assert(isn.ops[1].type == OperandType::Reg);
//			assert(isn.ops[0].size == 8 && isn.ops[1].size == 16);
//		}
//		else if (isn.ops[1].type != OperandType::Reg)
//		{
//			// movsd reg, mem - zeroes out bits 64-127
//			assert(isn.ops[0].type == OperandType::Reg);
//			assert(isn.ops[1].type == OperandType::Mem || isn.ops[1].type == OperandType::MemRVA);
//			assert(isn.ops[0].size == 16 && isn.ops[1].size == 8);
//		}
//		else
//		{
//			// movsd reg, reg - keeps bits 64+ untouched
//			assert(isn.ops[0].type == OperandType::Reg);
//			assert(isn.ops[1].type == OperandType::Reg);
//			assert(isn.ops[0].size == 16 && isn.ops[1].size == 16);
//		}
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = derefLoad(operandAddress(isn, isn.ops[1]), 8, isn.rva);
//		derefStore(dest, 8, isn.rva, value);
//		if (isn.ops[1].type != OperandType::Reg)
//			derefStore(dest.value.ptr + 8, 8, isn.rva, 0);
//	}
//
//	void emulateAdd(const Instruction& isn)
//	{
//		// TODO: add x, x ==> x *= 2 ??? or this should be handled by simplifier?
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size == isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = read(isn, isn.ops[1]);
//		auto modified = simplifyAdd(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), value);
//		derefStore(dest, isn.ops[0].size, isn.rva, modified);
//	}
//
//	void emulateSub(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size == isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
//		{
//			// sub x, x ==> x = 0
//			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
//			derefStore(dest, isn.ops[0].size, isn.rva, 0);
//		}
//		else
//		{
//			assert(isn.ops[0].size == 8); // TODO: sub reg,xxx with non-8 size
//			auto value = read(isn, isn.ops[1]);
//			auto modified = simplifyAdd(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), simplifyNeg(isn.rva, isn.ops[1].size, value));
//			derefStore(dest, isn.ops[0].size, isn.rva, modified);
//		}
//	}
//
//	void emulateIMul(const Instruction& isn)
//	{
//		ensure(isn.opcount == 3); // TODO: 1-operand and 2-operand forms
//		assert(isn.ops[0].size == isn.ops[1].size && isn.ops[0].size == isn.ops[2].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto modified = simplifyMul(isn.rva, isn.ops[0].size, read(isn, isn.ops[1]), read(isn, isn.ops[2]));
//		derefStore(dest, isn.ops[0].size, isn.rva, modified);
//	}
//
//	void emulateXor(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size == isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		if (isn.ops[0].type == OperandType::Reg && isn.ops[1].type == OperandType::Reg && isn.ops[0].reg == isn.ops[1].reg)
//		{
//			// xor x, x ==> x = 0
//			assert(isn.ops[0].size >= 4); // TODO: implement partial register clears?..
//			derefStore(dest, isn.ops[0].size, isn.rva, 0);
//		}
//		else
//		{
//			auto value = read(isn, isn.ops[1]);
//			auto modified = simplifyXor(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), value);
//			derefStore(dest, isn.ops[0].size, isn.rva, modified);
//		}
//	}
//
//	void emulateOr(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[0].size == isn.ops[1].size);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto value = read(isn, isn.ops[1]);
//		auto modified = simplifyOr(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), value);
//		derefStore(dest, isn.ops[0].size, isn.rva, modified);
//	}
//
//	void emulatePush(const Instruction& isn)
//	{
//		assert(isn.opcount == 1 && isn.ops[0].size == 8);
//		// push x ==> sub rsp, 8 + mov [rsp], x
//		auto rsp = AnalysisPointer{ AnalysisState::AS_Register, Register::toOffsetSize(X86_REG_RSP).first };
//		auto rspValue = derefLoad(rsp, 8, isn.rva);
//		assert(rspValue.type == AnalysisValueType::Pointer && rspValue.value.ptr.addressSpace == AnalysisState::AS_Stack);
//		rspValue.value.ptr -= 8;
//		derefStore(rsp, 8, isn.rva, rspValue);
//		derefStore(rspValue, isn.ops[0].size, isn.rva, read(isn, isn.ops[0]));
//	}
//
//	void emulateInc(const Instruction& isn)
//	{
//		assert(isn.opcount == 1);
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto modified = simplifyAdd(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), 1);
//		derefStore(dest, isn.ops[0].size, isn.rva, modified);
//	}
//
//	void emulateBtc(const Instruction& isn)
//	{
//		assert(isn.opcount == 2);
//		assert(isn.ops[1].type == OperandType::Imm); // TODO: handle version with register?..
//		assert(isn.ops[1].size == 1);
//		// btc x, imm ==> xor x, (1 << imm)
//		auto dest = operandAddress(isn, isn.ops[0]);
//		auto modified = simplifyXor(isn.rva, isn.ops[0].size, derefLoad(dest, isn.ops[0].size, isn.rva), 1ll << isn.imm);
//		derefStore(dest, isn.ops[0].size, isn.rva, modified);
//	}
//
//	void emulateCall(const Instruction& isn)
//	{
//		assert(isn.opcount == 1);
//		auto callee = read(isn, isn.ops[0]);
//		// TODO: not sure what we want to do with arguments here...
//		auto& state = mExitStates[mCurrentBlockIndex];
//		auto a1 = state.addressSpaces[AnalysisState::AS_Register].find(Register::toOffsetSize(X86_REG_RCX).first);
//		auto a2 = state.addressSpaces[AnalysisState::AS_Register].find(Register::toOffsetSize(X86_REG_RDX).first);
//		auto a3 = state.addressSpaces[AnalysisState::AS_Register].find(Register::toOffsetSize(X86_REG_R8).first);
//		auto a4 = state.addressSpaces[AnalysisState::AS_Register].find(Register::toOffsetSize(X86_REG_R9).first);
//		auto argsRest = derefLoad(AnalysisPointer{ AnalysisState::AS_Register, Register::toOffsetSize(X86_REG_RSP).first }, 8, isn.rva);
//		assert(argsRest.type == AnalysisValueType::Pointer && argsRest.value.ptr.addressSpace == AnalysisState::AS_Stack);
//		argsRest.value.ptr += 0x20;
//		// clear all volatile registers
//		// TODO: clear part of stack too? does it even matter?
//		state.addressSpaces[AnalysisState::AS_Register].eraseEntries(Register::toOffsetSize(X86_REG_RAX).first, Register::toRange(X86_REG_RDX).second); // rax/rcx/rdx are contiguous
//		state.addressSpaces[AnalysisState::AS_Register].eraseEntries(Register::toOffsetSize(X86_REG_R8).first, Register::toRange(X86_REG_R10).second); // r8/r9/r10 are contiguous
//		state.addressSpaces[AnalysisState::AS_Register].eraseEntries(Register::toOffsetSize(X86_REG_ZMM0).first, Register::toRange(X86_REG_ZMM5).second); // xmm0-xmm5 are volatile; TODO: upper portions of xmm6-15 are too...
//		state.addressSpaces[AnalysisState::AS_Register].eraseEntries(Register::toOffsetSize(X86_REG_ZMM16).first, Register::toRange(X86_REG_ZMM31).second);
//		derefStore(regToPtr(X86_REG_RAX, 8), 8, isn.rva, addExpression(isn.rva, AnalysisExpression(8, AnalysisExpressionOp::Call, callee)));
//	}
//
//	void emulateInt(const Instruction& isn)
//	{
//		assert(isn.opcount == 1 && isn.ops[0].type == OperandType::Imm);
//		ensure(isn.imm == 0x29); // fastfail
//	}
//
//	AnalysisPointer regToPtr(x86_reg reg, int expectedSize)
//	{
//		auto [offset, size] = Register::toOffsetSize(reg);
//		ensure(size == expectedSize);
//		return AnalysisPointer{ AnalysisState::AS_Register, offset };
//	}
//
//	// think what 'lea' does, but also supports registers - convert reg/mem operand to an 'address'
//	// note that it might return any type (e.g. constant if operand is [addr], or an expression ref if operand is something like [rcx] where rcx value is unknown
//	// registers are converted to pointers into 'register file' address space
//	AnalysisValueWithType operandAddress(const Instruction& isn, const Operand& operand)
//	{
//		if (operand.type == OperandType::Reg)
//		{
//			return regToPtr(operand.reg, operand.size);
//		}
//		else
//		{
//			assert(operand.type == OperandType::Mem || operand.type == OperandType::MemRVA);
//			auto res = operandAddressBase(isn, operand.type == OperandType::MemRVA);
//			res = simplifyAdd(isn.rva, 8, res, isn.mem.disp);
//			if (isn.mem.index != X86_REG_INVALID && isn.mem.scale != 0)
//			{
//				auto index = derefLoad(regToPtr(isn.mem.index, 8), 8, isn.rva);
//				res = simplifyAdd(isn.rva, 8, res, simplifyMul(isn.rva, 8, index, isn.mem.scale));
//			}
//			return res;
//		}
//	}
//
//	AnalysisValueWithType operandAddressBase(const Instruction& isn, bool rvaBase)
//	{
//		if (rvaBase)
//		{
//			assert(isn.mem.segment == X86_REG_INVALID);
//			return AnalysisPointer{ AnalysisState::AS_Global };
//		}
//		else if (isn.mem.segment == X86_REG_INVALID)
//		{
//			assert(isn.mem.base != X86_REG_INVALID);
//			return derefLoad(regToPtr(isn.mem.base, 8), 8, isn.rva);
//		}
//		else if (isn.mem.segment == X86_REG_GS)
//		{
//			AnalysisValueWithType base = isn.mem.base != X86_REG_INVALID ? derefLoad(regToPtr(isn.mem.base, 8), 8, isn.rva) : 0;
//			return simplifyAdd(isn.rva, 8, AnalysisPointer{ AnalysisState::AS_TEB }, base);
//		}
//		else
//		{
//			__debugbreak(); // TODO
//			return{};
//		}
//	}
//
//	// load value stored at specified address
//	AnalysisValueWithType derefLoad(AnalysisValueWithType address, int size, rva_t rva)
//	{
//		auto value = derefLoadNoLog(address, size, rva);
//		log(">>> load {}b {} = {}", size, address, value);
//		if (address.type == AnalysisValueType::Expression)
//			log(">>>> {} == {}", address, mExpressions[address.value.expr.index]);
//		if (value.type == AnalysisValueType::Expression)
//			log(">>>> {} == {}", value, mExpressions[value.value.expr.index]);
//		return value;
//	}
//
//	AnalysisValueWithType derefLoadNoLog(AnalysisValueWithType address, int size, rva_t rva)
//	{
//		if (auto expr = exprWithOp(address, AnalysisExpressionOp::Add); expr && expr->operandType[1] == AnalysisValueType::Pointer)
//		{
//			// address + some unknown offset...
//			__debugbreak();
//			address = expr->getOperand(1);
//		}
//
//		if (address.type != AnalysisValueType::Pointer)
//			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address)); // fallback, we don't know how to dereference non-pointer properly
//
//		auto entryEnd = address.value.ptr.offset + size;
//		auto& space = mExitStates[mCurrentBlockIndex].addressSpaces[address.value.ptr.addressSpace];
//		auto next = space.findNext(address.value.ptr.offset);
//		if (next != space.end() && next->begin < entryEnd)
//		{
//			// partial overlap with high bytes
//			// TODO: merge constants...
//			__debugbreak();
//			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
//		}
//
//		if (next == space.begin() || (next - 1)->end <= address.value.ptr.offset)
//		{
//			// read of fully uninitialized memory
//			// add a new expression, so that subsequent reads return same one
//			auto value = addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
//			space.insert({ address.value.ptr.offset, address.value.ptr.offset + size, value });
//			return value;
//		}
//
//		auto prev = next - 1;
//		if (prev->begin < address.value.ptr.offset)
//		{
//			// partial overlap with low bytes
//			// TODO: merge constants...
//			__debugbreak();
//			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
//		}
//
//		if (prev->end == entryEnd)
//		{
//			// good path
//			return prev->value;
//		}
//		else if (prev->end < entryEnd)
//		{
//			// read of partially written value - what to do?..
//			__debugbreak();
//			return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
//		}
//
//		// at this point we're dealing with partial read
//		if (prev->value.type == AnalysisValueType::Constant)
//		{
//			// partial read of constant
//			auto value = prev->value.value.constant & ((1ull << 8 * size) - 1);
//			return makeConstant(value, size);
//		}
//		else if (prev->value.type == AnalysisValueType::Expression)
//		{
//			auto& expr = mExpressions[prev->value.value.expr.index];
//			if (expr.size == size)
//			{
//				// TODO: reconsider (this deals with mov eax, expr - that was zero-extended to rax etc)
//				return prev->value;
//			}
//
//			if ((expr.op == AnalysisExpressionOp::SignExtend || expr.op == AnalysisExpressionOp::ZeroExtend) && expr.operandType[0] == AnalysisValueType::Expression && mExpressions[expr.operandValue[0].expr.index].size == size)
//			{
//				// TODO: reconsider (this deals with movzx eax, word/byte + mov word, ax)
//				return expr.getOperand(0);
//			}
//		}
//
//		// TODO: other partial reads - what to do?.. can have something like & 0xFFFF....
//		__debugbreak();
//		return addExpression(rva, AnalysisExpression(size, AnalysisExpressionOp::Deref, address));
//	}
//
//	// store specified value at specified address
//	void derefStore(AnalysisValueWithType address, int size, rva_t rva, AnalysisValueWithType value)
//	{
//		log(">>> store {}b {} = {}", size, address, value);
//		if (address.type == AnalysisValueType::Expression)
//			log(">>>> {} == {}", address, mExpressions[address.value.expr.index]);
//		if (value.type == AnalysisValueType::Expression)
//			log(">>>> {} == {}", value, mExpressions[value.value.expr.index]);
//
//		assert(value.type != AnalysisValueType::Unknown);
//		ensure(value.type != AnalysisValueType::Pointer || size == 8); // chopping pointers is probably not correct?..
//		ensure(value.type != AnalysisValueType::Expression || mExpressions[value.value.expr.index].size == size);
//
//		if (address.type != AnalysisValueType::Pointer)
//		{
//			__debugbreak(); // TODO: if we care, record off the side - but we can't really update the state anyway (so any potential aliasing is lost)
//			return;
//		}
//
//		if (address.value.ptr.addressSpace == AnalysisState::AS_Register && size == 4)
//		{
//			// dword register writes automatically clear high dword
//			size = 8;
//			if (value.type == AnalysisValueType::Constant)
//				value.value.constant &= 0xFFFFFFFF;
//			// TODO: for expressions - consider wrapping into a zero-extend unary op?.. might complicate things a bit...
//		}
//
//		auto entryEnd = address.value.ptr.offset + size;
//		auto& space = mExitStates[mCurrentBlockIndex].addressSpaces[address.value.ptr.addressSpace];
//		auto next = space.findNext(address.value.ptr.offset);
//		if (next != space.end() && next->begin < entryEnd)
//		{
//			// we have some partial overlaps - full overlaps can be deleted (since they are fully overwritten)
//			auto overlapEnd = next + 1;
//			while (overlapEnd != space.end() && overlapEnd->end <= entryEnd)
//				++overlapEnd;
//
//			if (overlapEnd != space.end() && overlapEnd->begin < entryEnd)
//			{
//				// partial overlap - some low bytes are to be discarded
//				// TODO: implement as generic byte-extract / shift?..
//				if (overlapEnd->value.type == AnalysisValueType::Constant)
//				{
//					space.edit(overlapEnd).value.value.constant >>= 8 * (entryEnd - overlapEnd->begin);
//					space.shrink(entryEnd, overlapEnd->end, overlapEnd);
//				}
//				else
//				{
//					__debugbreak();
//					++overlapEnd; // forgetting stuff always works...
//				}
//			}
//
//			next = space.erase(next, overlapEnd);
//		}
//		// at this point, if next exists, it does not overlap the entry
//
//		if (next == space.begin() || (next - 1)->end <= address.value.ptr.offset)
//		{
//			// no overlaps, just insert new entry
//			space.insert({ address.value.ptr.offset, entryEnd, value }, next);
//			return;
//		}
//
//		// ok, so there's some overlap between existing and new ranges - we might have bytes to chop on either side, and then might need to extend the remaining entry
//		auto prev = next - 1;
//		if (prev->begin < address.value.ptr.offset)
//		{
//			// insert new entry before prev containing chopped off low bytes
//			// TODO: implement this generically?
//			if (prev->value.type == AnalysisValueType::Constant)
//			{
//				auto addr = prev->begin;
//				AnalysisValueWithType low = prev->value.value.constant & ((1ull << 8 * (address.value.ptr.offset - prev->begin)) - 1);
//				space.shrink(address.value.ptr.offset, prev->end, prev);
//				prev = space.insert({ addr, address.value.ptr.offset, low }, prev);
//			}
//			else
//			{
//				// just shrink the entry, effectively forgetting low bytes
//				__debugbreak();
//				space.shrink(address.value.ptr.offset, prev->end, prev);
//			}
//		}
//
//		if (prev->end > entryEnd)
//		{
//			// insert new entry after prev containing chopped off high bytes
//			// TODO: implement as generic byte-extract / shift?..
//			if (prev->value.type == AnalysisValueType::Constant)
//			{
//				auto end = prev->end;
//				AnalysisValueWithType high = prev->value.value.constant >> 8 * (end - entryEnd);
//				space.shrink(prev->begin, entryEnd, prev);
//				prev = space.insert({ entryEnd, end, high }, prev + 1) - 1;
//			}
//			else
//			{
//				// just shrink the entry, effectively forgetting high bytes
//				space.shrink(prev->begin, entryEnd, prev);
//			}
//		}
//
//		if (prev->end < entryEnd)
//		{
//			// existing entry just needs to be extended - this is fine, we'll overwrite it fully
//			space.extend(prev->end, entryEnd, prev + 1);
//		}
//
//		// happy path - existing entry covers exactly same region as new one, so just overwrite
//		space.edit(prev).value = value;
//	}
//
//	// read value specified by an operand
//	// if value is currently undefined, creates new expression implicitly
//	AnalysisValueWithType read(const Instruction& isn, const Operand& operand)
//	{
//		switch (operand.type)
//		{
//		case OperandType::Invalid:
//			return{};
//		case OperandType::Imm:
//			return makeConstant(isn.imm, operand.size);
//		case OperandType::ImmRVA:
//			return AnalysisPointer{ AnalysisState::AS_Global, static_cast<i32>(isn.imm) };
//		default:
//			return derefLoad(operandAddress(isn, operand), operand.size, isn.rva);
//		}
//	}
//
//	AnalysisExpressionRef addExpression(rva_t rva, AnalysisExpression expr)
//	{
//		expr.rva = rva;
//		expr.blockIndex = mCurrentBlockIndex;
//		auto index = mExpressions.size();
//		mExpressions.push_back(expr);
//		return{ index };
//	}
//
//	AnalysisValueWithType makeConstant(i64 value, int size)
//	{
//		switch (size)
//		{
//		case 1: return (i8)value;
//		case 2: return (i16)value;
//		case 4: return (i32)value;
//		case 8: return (i64)value;
//		default: throw std::exception("Unexpected size");
//		}
//	}
//
//	AnalysisValueWithType simplifyNeg(rva_t rva, int size, AnalysisValueWithType v)
//	{
//		if (v.type == AnalysisValueType::Constant)
//			return makeConstant(-v.value.constant, size);
//
//		if (v.type == AnalysisValueType::Expression)
//		{
//			auto& e = mExpressions[v.value.expr.index];
//			switch (e.op)
//			{
//			case AnalysisExpressionOp::Neg: return e.getOperand(0); // -(-x) == x
//			case AnalysisExpressionOp::Add: return simplifyAdd(rva, size, simplifyNeg(rva, size, e.getOperand(0)), simplifyNeg(rva, size, e.getOperand(1))); // -(a + b) == (-a) + (-b)
//			}
//		}
//
//		return addExpression(rva, { size, AnalysisExpressionOp::Neg, v });
//	}
//
//	AnalysisValueWithType simplifySignExtend(rva_t rva, int size, AnalysisValueWithType v, int originalSize)
//	{
//		assert(size > originalSize);
//		switch (v.type)
//		{
//		case AnalysisValueType::Constant:
//			return makeConstant(v.value.constant, originalSize);
//		case AnalysisValueType::Expression:
//			assert(mExpressions[v.value.expr.index].size == originalSize);
//			// TODO: simplify - extend extended
//			return addExpression(rva, { size, AnalysisExpressionOp::SignExtend, v });
//		default:
//			throw std::exception("Unexpected value type");
//		}
//	}
//
//	AnalysisValueWithType simplifyZeroExtend(rva_t rva, int size, AnalysisValueWithType v, int originalSize)
//	{
//		assert(size > originalSize);
//		switch (v.type)
//		{
//		case AnalysisValueType::Constant:
//			return v.value.constant & ((1ull << 8 * originalSize) - 1);
//		case AnalysisValueType::Expression:
//			assert(mExpressions[v.value.expr.index].size == originalSize);
//			// TODO: simplify - extend extended
//			return addExpression(rva, { size, AnalysisExpressionOp::ZeroExtend, v });
//		default:
//			throw std::exception("Unexpected value type");
//		}
//	}
//
//	AnalysisValueWithType simplifyAdd(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
//	{
//		// TODO: a * b + c * b ==> (a + c) * b ?
//		return simplifyBinaryCommAssoc(rva, size, lhs, AnalysisExpressionOp::Add, rhs, [this](rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs) -> AnalysisValueWithType {
//			if (lhs.type == AnalysisValueType::Constant)
//			{
//				assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
//				return makeConstant(lhs.value.constant + rhs.value.constant, size);
//			}
//
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == 0)
//				return lhs; // no-op
//
//			if (lhs.type == AnalysisValueType::Pointer && rhs.type == AnalysisValueType::Constant)
//				return lhs.value.ptr + rhs.value.constant;
//
//			// TODO: ptr(ASx) + neg(ptr(ASx)) ==> constant
//			if (matchUnaryExpr(lhs, AnalysisExpressionOp::Neg, rhs) || matchUnaryExpr(rhs, AnalysisExpressionOp::Neg, lhs))
//				return 0; // (-x) + x ==> 0
//			if (matchUnaryExpr(lhs, AnalysisExpressionOp::Not, rhs) || matchUnaryExpr(rhs, AnalysisExpressionOp::Not, lhs))
//				return -1; // (~x) + x ==> -1
//
//			return{};
//		});
//	}
//
//	AnalysisValueWithType simplifyMul(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
//	{
//		// TODO: interop with add - eg something like c1 * x + c2 * x ==> (c1 + c2) * x
//		return simplifyBinaryCommAssoc(rva, size, lhs, AnalysisExpressionOp::MulLo, rhs, [this](rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs) -> AnalysisValueWithType {
//			if (lhs.type == AnalysisValueType::Constant)
//			{
//				assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
//				return makeConstant(lhs.value.constant * rhs.value.constant, size);
//			}
//
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == 0)
//				return 0;
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == 1)
//				return lhs; // no-op
//			// TODO: x * (-1) ==> neg(x) ?
//
//			return{};
//		});
//	}
//
//	AnalysisValueWithType simplifyXor(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
//	{
//		return simplifyBinaryCommAssoc(rva, size, lhs, AnalysisExpressionOp::Xor, rhs, [this](rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs) -> AnalysisValueWithType {
//			if (lhs.type == AnalysisValueType::Constant)
//			{
//				assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
//				return makeConstant(lhs.value.constant ^ rhs.value.constant, size);
//			}
//
//			// TODO: x ^ -1 ==> ~x ?
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == 0)
//				return lhs; // no-op
//
//			if (lhs == rhs)
//				return 0; // x ^ x ==> 0
//			if (matchUnaryExpr(lhs, AnalysisExpressionOp::Not, rhs) || matchUnaryExpr(rhs, AnalysisExpressionOp::Not, lhs))
//				return -1; // (~x) ^ x ==> -1
//
//			return{};
//		});
//	}
//
//	AnalysisValueWithType simplifyOr(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs)
//	{
//		return simplifyBinaryCommAssoc(rva, size, lhs, AnalysisExpressionOp::Or, rhs, [this](rva_t rva, int size, AnalysisValueWithType lhs, AnalysisValueWithType rhs) -> AnalysisValueWithType {
//			if (lhs.type == AnalysisValueType::Constant)
//			{
//				assert(rhs.type == AnalysisValueType::Constant); // otherwise we'd have swapped
//				return makeConstant(lhs.value.constant | rhs.value.constant, size);
//			}
//
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == 0)
//				return lhs; // no-op
//			if (rhs.type == AnalysisValueType::Constant && rhs.value.constant == -1)
//				return -1;
//
//			if (lhs == rhs)
//				return lhs; // x | x ==> x
//			if (matchUnaryExpr(lhs, AnalysisExpressionOp::Not, rhs) || matchUnaryExpr(rhs, AnalysisExpressionOp::Not, lhs))
//				return -1; // (~x) | x ==> -1
//
//			return{};
//		});
//	}
//
//	// note: FnSimplify should not create new expressions - these might get discarded
//	template<typename FnSimplify>
//	AnalysisValueWithType simplifyBinaryCommAssoc(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisExpressionOp op, AnalysisValueWithType rhs, FnSimplify&& simplify)
//	{
//		commAssocSwapIfNeeded(lhs, op, rhs);
//
//		if (auto r = exprWithOp(rhs, op))
//		{
//			assert(r->size == size);
//			assert(exprWithOp(lhs, op)); // otherwise we'd have swapped
//			// (a op b) op (c op d) ==> ((a op b) op c) op d
//			// TODO: do we really want to do that?.. this introduces tons of new expressions at same rva... maybe leave as is, unless some pair is special-case-simplifiable?..
//			auto right = r->getOperand(1); // r is invalidated when new expressions are added
//			auto inner = simplifyBinaryCommAssoc(rva, size, lhs, op, r->getOperand(0), std::forward<FnSimplify>(simplify));
//			return simplifyBinaryCommAssoc(rva, size, inner, op, right, std::forward<FnSimplify>(simplify));
//		}
//
//		if (auto simplified = simplifyBinaryCommAssocRecurse(rva, size, lhs, op, rhs, std::forward<FnSimplify>(simplify)); simplified.type != AnalysisValueType::Unknown)
//			return simplified;
//
//		// nope, we can't simplify anything - just create a new binary expression
//		// we might need to swap operands around for nested expression to maintain ordering
//		if (auto l = exprWithOp(lhs, op); l && priorityForCommAssoc(l->getOperand(1), op) < priorityForCommAssoc(rhs, op))
//		{
//			// something like (x + const) + expr ==> (x + expr) + const
//			auto right = l->getOperand(1);
//			auto inner = simplifyBinaryCommAssoc(rva, size, l->getOperand(0), op, rhs, std::forward<FnSimplify>(simplify));
//			return simplifyBinaryCommAssoc(rva, size, inner, op, right, std::forward<FnSimplify>(simplify));
//		}
//
//		return addExpression(rva, { size, lhs, op, rhs });
//	}
//
//	template<typename FnSimplify>
//	AnalysisValueWithType simplifyBinaryCommAssocRecurse(rva_t rva, int size, AnalysisValueWithType lhs, AnalysisExpressionOp op, AnalysisValueWithType rhs, FnSimplify&& simplify)
//	{
//		assert(!exprWithOp(rhs, op)); // this should be handled by the caller
//
//		// try direct simplification first
//		if (auto res = simplify(rva, size, lhs, rhs); rhs.type != AnalysisValueType::Unknown)
//			return res;
//
//		// see if lhs is nested op
//		if (auto l = exprWithOp(lhs, op))
//		{
//			// (a op b) op c
//			assert(l->size == size);
//			auto a = l->getOperand(0);
//			auto b = l->getOperand(1);
//			assert(!exprWithOp(b, op)); // this would violate associativity form
//
//			// first check whether (b op c) is simplifiable - and if so, replace with a op (b op c)
//			if (auto bc = simplify(rva, size, b, rhs); bc.type != AnalysisValueType::Unknown)
//				return simplifyBinaryCommAssoc(rva, size, a, op, bc, std::forward<FnSimplify>(simplify));
//
//			// and now check (a op c) - this has to be done recursively, since a might be a nested op
//			if (auto ac = simplifyBinaryCommAssocRecurse(rva, size, a, op, rhs, std::forward<FnSimplify>(simplify)); ac.type != AnalysisValueType::Unknown)
//				return simplifyBinaryCommAssoc(rva, size, ac, op, b, std::forward<FnSimplify>(simplify));
//		}
//
//		// nope, can't simplify - return nothing to let caller try again
//		return{};
//	}
//
//	// associativeness: nested is always on the left
//	// commutativeness: constant > pointer > other-op expr > same-op expr priority for right-side, this simplifies constant propagation
//	int priorityForCommAssoc(AnalysisValueWithType v, AnalysisExpressionOp op)
//	{
//		switch (v.type)
//		{
//		case AnalysisValueType::Constant: return 0;
//		case AnalysisValueType::Pointer: return 1;
//		case AnalysisValueType::Expression: return mExpressions[v.value.expr.index].op == op ? 3 : 2;
//		default: throw std::exception("Bad type");
//		}
//	}
//
//	void commAssocSwapIfNeeded(AnalysisValueWithType& lhs, AnalysisExpressionOp op, AnalysisValueWithType& rhs)
//	{
//		if (priorityForCommAssoc(lhs, op) < priorityForCommAssoc(rhs, op))
//			std::swap(rhs, lhs);
//	}
//
//	// return expression referred to by the value, if it has specified op, or null otherwise
//	AnalysisExpression* exprWithOp(AnalysisValueWithType v, AnalysisExpressionOp op)
//	{
//		if (v.type != AnalysisValueType::Expression)
//			return nullptr;
//		auto& expr = mExpressions[v.value.expr.index];
//		return expr.op == op ? &expr : nullptr;
//	}
//
//	// check whether given value is an unary expression with specified argument
//	bool matchUnaryExpr(AnalysisValueWithType v, AnalysisExpressionOp op, AnalysisValueWithType arg)
//	{
//		auto expr = exprWithOp(v, op);
//		return expr && expr->getOperand(0) == arg;
//	}
//
//	template<typename... Args> void log(const std::format_string<Args...> fmt, Args&&... args)
//	{
//		if (mLog)
//			std::println(fmt, std::forward<Args>(args)...);
//	}
//
//private:
//	std::vector<AnalysisBlock> mBlocks; // sorted in topological (reverse-post) order
//	std::vector<AnalysisState> mExitStates;
//	std::vector<AnalysisExpression> mExpressions;
//	int mCurrentBlockIndex = -1;
//	const PEBinary& mBin;
//	bool mLog = false;
//};
