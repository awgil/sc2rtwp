export module unpack.analysis.simple_refs;

export import unpack.x86.instruction;

namespace analysis {

export struct Reference
{
	const x86::Instruction* ins;
	int iop;
	i32 ref;
	// TODO: reference type? or maybe it should be part of operand structure?
};

i32 getJumpTargetIfExternal(const x86::Instruction& ins, std::span<const x86::Instruction> range)
{
	if (ins.ops[0].type != x86::OpType::Imm)
		return 0;
	auto value = ins.ops[0].immediate<i32>();
	if (ins.mnem == X86_INS_CALL)
		return value;
	if (ins.mnem == X86_INS_JMP || ins.mnem.isConditionalJump())
		return value >= range.front().rva && value < range.back().endRVA() ? 0 : value;
	return 0;
}

// list all references to globals for given instructions
// note: this only finds 'simple' references, eg if the code loads imagebase into a register and then does register-relative addresses, these won't be found
export std::vector<Reference> getSimpleRefs(std::span<const x86::Instruction> instructions)
{
	std::vector<Reference> refs;
	for (auto& ins : instructions)
	{
		for (int iop = 0; auto& op : ins.operands())
		{
			if (op.type == x86::OpType::Mem && op.mem.base == x86::Reg::imagebase)
			{
				refs.push_back({ &ins, iop, op.mem.displacement });
			}
			++iop;
		}

		// deal with relative calls/jumps
		if (auto target = getJumpTargetIfExternal(ins, instructions))
		{
			refs.push_back({ &ins, 0, target });
		}
	}
	return refs;
}


}
