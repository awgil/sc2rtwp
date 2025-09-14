#include <common/win_headers.h>
#include <capstone/capstone.h>

import std;
import common;
import unpack.pe_binary;
import unpack.function;
import unpack.analysis;
import unpack.known_structs;

template<typename T, typename F> constexpr size_t fieldOffset(F (T::*f))
{
	auto& pm = static_cast<T*>(nullptr)->*f;
	return reinterpret_cast<size_t>(&pm);
}

// address of some entity in the executable
// initially it's location is unknown; when we discover first reference, we save the RVA - and then validate that all other references match
class ResolvedAddress
{
public:
	bool resolved() const { return mRVA; }
	auto address() const { ensure(resolved()); return mRVA; }

	void resolve(rva_t rva)
	{
		if (!mRVA)
			mRVA = rva;
		else
			ensure(mRVA == rva);
	}

private:
	rva_t mRVA = 0; // 0 until discovered
};

// address of a global structure; resolved by field accesses
template<typename T> class ResolvedGlobalAddress : public ResolvedAddress
{
public:
	T* access(PEBinary& bin) const { return bin.structAtRVA<T>(address()); }
};

template<typename T> T getSimpleXorConstant(PEBinary& bin, const FunctionInfo& func, const FunctionInfo::Reference& ref)
{
	auto block = ensure(func.findBlock(ref.insnRVA));
	auto it = block->findInstruction(ref.insnRVA);
	ensure(it != block->instructions.end());
	// supported sequences:
	//                            xor r1, const; mov mem, r1
	// mov r2, const;             xor r1, r2;    mov mem, r1
	// mov r2, const; mov r1, r3; xor r1, r2;    mov mem, r1

	T constant = 0;
	ensure(it->mnem == X86_INS_MOV && it->opcount == 2 && (it->ops[0].type == OperandType::Mem || it->ops[0].type == OperandType::MemRVA) && it->ops[1].type == OperandType::Reg);
	auto finalReg = it->ops[1].reg;

	ensure(it != block->instructions.begin());
	--it;
	ensure(it->mnem == X86_INS_XOR && it->opcount == 2 && it->ops[0].type == OperandType::Reg && it->ops[0].reg == finalReg);
	if (it->ops[1].type == OperandType::Imm)
	{
		// simple form, xor with immediate
		constant = static_cast<T>(it->imm);
	}
	else if (it->ops[1].type == OperandType::Reg)
	{
		auto interReg = it->ops[1].reg;

		ensure(it != block->instructions.begin());
		--it;
		while (it->mnem == X86_INS_MOV)
		{
			ensure(it->opcount == 2 && it->ops[0].type == OperandType::Reg && it->ops[1].type == OperandType::Reg);
			if (finalReg == it->ops[0].reg)
				finalReg = it->ops[1].reg;
			else if (interReg == it->ops[0].reg)
				interReg = it->ops[1].reg;
			else
				throw std::exception("Unexpected mov");

			ensure(it != block->instructions.begin());
			--it;
		}

		ensure(it->mnem == X86_INS_MOVABS && it->opcount == 2 && it->ops[0].type == OperandType::Reg && it->ops[1].type == OperandType::Imm);
		ensure(it->ops[0].reg == interReg || it->ops[0].reg == finalReg);
		constant = static_cast<T>(it->imm);
	}
	else
	{
		throw std::exception("Unsupported xor operand");
	}

	// it so happens that initial value for a xorred value is equal to the xor constant (i.e. the initial effective value is zero)
	// nothing actually relies on that afaik, but it's a good sanity check
	auto initialValue = *bin.structAtRVA<T>(ref.refRVA);
	ensure(constant == initialValue);
	return constant;
}

// field which value is xorred by constant
template<typename T, typename C> class XorredField
{
public:
	XorredField(T (C::*field), std::string_view debugName) : mDebugName(debugName), mField(field) {}

	T constant() const { ensure(mConstant); return mConstant; }
	auto field() const { return mField; }

	void resolve(PEBinary& bin, const FunctionInfo& func, const FunctionInfo::Reference& ref)
	{
		auto value = getSimpleXorConstant<T>(bin, func, ref);
		if (mConstant == 0)
		{
			std::println("XOR constant 0x{:016X} for {} at {} written by instruction at {}", value, mDebugName, bin.formatRVA(ref.refRVA), bin.formatRVA(ref.insnRVA));
			mConstant = value;
		}
		else
		{
			ensure(mConstant == value);
		}
	}

private:
	T mConstant = 0; // 0 until resolved
	T (C::*mField);
	std::string_view mDebugName; // printed when it's resolved
};

// TODO: process entry point, tls callbacks, exports, reloc table (to find function addresses in vtables etc), SEH (handler/filter ptrs + function bounds)
// TODO: RTTI?
class SC2Binary
{
public:
	SC2Binary(const std::string& path)
		: mBinary(path.c_str())
		, mSectionText(mBinary.sections().getByName(".text"))
		, mSectionRData(mBinary.sections().getByName(".rdata"))
		, mSectionData(mBinary.sections().getByName(".data"))
		, mFuncs(mBinary)
	{
		ensure(&mSectionText - &*mBinary.sections().begin() == 0);
		ensure(&mSectionRData - &*mBinary.sections().begin() == 1);
		ensure(&mSectionData - &*mBinary.sections().begin() == 2);

		// note on relocs: SC2 binary has 0 relocs in .text section, which makes sense (there's stuff in vtables etc that needs to be relocated, code uses rip relative addressing modes everywhere...)
		// this means we can completely skip emulating all the manual relocation logic in decompressor
		for (auto reloc : mBinary.relocRVAs())
			ensure(!mSectionText.contains(reloc));

		processBootstrapStart();
		processTLSCallbacks();

		mBinary.save((path + "_fixed").c_str());
	}

private:
	// process fallback start function
	void processBootstrapStart()
	{
		auto& start = mFuncs.process(mBinary.entryPoint(), "bootstrapStart");
		auto ana = AnalyzedFunction{ start };

		matchDataFieldRefs(start, &BootstrapStartState::stage);
		matchTextReferences(start);
		ensure(mBSS.address() - mSectionData.begin == 0x60); // not sure what's there before it and how likely is it to change...
	}

	// process TLS callbacks that do the actual decoding
	void processTLSCallbacks()
	{
		// note: tls directory is in .rdata, just preceeding RTTI data...
		ensure(mBinary.tlsCallbackRVAs().size() == 1);
		auto& tlsInitial = mFuncs.process(mBinary.tlsCallbackRVAs().front(), "bootstrapTLSInitial");
		matchDataFieldRefs(tlsInitial,
			&BootstrapStartState::stage,
			&AntitamperStaticState::xorConstants,
			&AntitamperStaticState::supportSSE, // processor caps flags
			&AntitamperStaticState::pageHashUsesAVX2); // last flag
		matchTextReferences(tlsInitial, mTLSRuntime, mTLSDecode, mTLSFixup);
		// note: RTTI between tls directory and antidebug static ?..
		// TODO-UNPACK: only really need to write out processor caps; xor constants should be left as zeros...

		// main decoding tls callback
		auto& tlsDecodeImpl = processWrapperFunc(mTLSDecode.address(), "bootstrapTLSDecode", &BootstrapStartState::stage);
		// TODO: rest...

		auto iRef = tlsDecodeImpl.refs().begin();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		ensure(iRef++->refRVA == 0); // this is kinda bad, this is used to fill relocationsStraddlingPageBoundary
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::relocationsStraddlingPageBoundaryCount);
		processVEH(iRef++->refRVA);
		dumpRefs(tlsDecodeImpl);
		ensure(iRef == tlsDecodeImpl.refs().end());
	}

	// process everything related to VEH - it deals with creating one of the obfuscate() variants
	void processVEH(rva_t rvaSetupVEH)
	{
		auto& setupVEH = mFuncs.process(rvaSetupVEH, "bootstrapSetupVEH");
		matchDataFieldRefs(setupVEH,
			mXorRtlAddVectoredExceptionHandler,
			mXorRtlAddVectoredExceptionHandler.field(),
			&AntitamperStaticState::bootstrapVEHHandle,
			&AntitamperStaticState::xorredSectionMapping,
			&AntitamperStaticState::vehDecryptionDone,
			mXorCloseHandle,
			mXorVirtualAlloc,
			mXorNtCreateSection,
			mXorMapViewOfFileEx,
			mXorVirtualProtect,
			mXorUnmapViewOfFile,
			mXorRemoveVectoredExceptionHandler);
		matchTextReferences(setupVEH, mVEHMain);

		auto& vehMainImpl = processWrapperFunc(mVEHMain.address(), "bootstrapVEHMain");
		matchDataFieldRefs(vehMainImpl,
			&AntitamperStaticState::bootstrapVEHInvocationCount, // comparison, reset & increment
			&AntitamperStaticState::bootstrapVEHInvocationCount,
			&AntitamperStaticState::bootstrapVEHInvocationCount,
			mXorVEHRetval,
			mXorVEHRetval.field(),
			mXorVEHLastExcInfo,
			&BootstrapStartState::vehVal4,
			&BootstrapStartState::vehVal1,
			&AntitamperStaticState::xorredSectionMapping,
			&AntitamperStaticState::bootstrapRegionHash,
			&AntitamperStaticState::bootstrapRegionHash,
			&AntitamperStaticState::bootstrapRegionHashMismatch,
			&AntitamperStaticState::bootstrapRegionHashMismatch,
			mXorVEHRetval.field(),
			&BootstrapStartState::vehVal11,
			&BootstrapStartState::vehVal11,
			&BootstrapStartState::vehVal11,
			&BootstrapStartState::vehVal2,
			&BootstrapStartState::vehVal6,
			&BootstrapStartState::vehVal9,
			&BootstrapStartState::vehVal9,
			&BootstrapStartState::vehVal9);
		matchNonCallTextReferences(vehMainImpl, mVEHHashRegionEnd, mVEHHashRegionStart, mVEHContinuationFail);

		ensure(mVEHHashRegionEnd.address() > mVEHHashRegionStart.address());

		auto& vehContinuationFail = mFuncs.process(mVEHContinuationFail.address(), "bootstrapVEHContinuationFail");
		ensure(vehContinuationFail.refs().empty());

		for (auto [i, call] : std::ranges::views::enumerate(vehMainImpl.calls()))
			processVEHSub(call.refRVA, i + 1);
	}

	// note: index is 1-based for legacy reasons (that's how i called subfunctions while reversing)
	void processVEHSub(rva_t rva, int index)
	{
		ensure(index > 0 && index <= 15);
		auto& vehSub = mFuncs.process(rva, std::format("bootstrapVEHSub{}", index));
		// all VEH sub-functions are built similarly:
		// if (gLastExcInfo.get()->Context->Dr7) goto fail; // prologue data access #1
		// if (gNumCallsN == k1) // prologue data access #2
		//   ... function-specific payload
		// if (gNumCallsN >= k2 + (random % 1024)) return true; // epilogue data access #1
		// if (gHashRegionMismatch) { // epilogue data access #2
		//   fail: // hw bps jump here
		//     gLastExcInfo.get()->Context->Rdx = 0; // epilogue data access #3
		//     gLastExcInfo.get()->Context->Rip = bootstrapVEHContinuationFail; // epilogie data access #4 and code access #1
		//     gRetval.set(EXCEPTION_CONTINUE_EXECUTION); // epilogue data access #5
		//     return false;
		// }
		// ++gNumCallsN; // epiligue data access #6
		// return false;
		ensure(vehSub.refs().size() >= 9);
		auto iRef = vehSub.refs().begin();

		// match prologue
		matchDataFieldRef(vehSub, *iRef++, mXorVEHLastExcInfo.field());
		auto numCallsRVA = mASS.address() + fieldOffset(&AntitamperStaticState::bootstrapVEHSubInvocationCount) + sizeof(u32) * (index - 1);
		ensure(iRef++->refRVA == numCallsRVA);

		//std::println("VEH sub {}:", index);
		//for (auto& ref : vehSub.refs())
		//	std::println("-> {}", mBinary.formatRVA(ref.refRVA));

		// bootstrap region rehash logic is repeated in a few functions
		if (index == 1 || index == 2 || index == 5 || index == 8 || index == 10)
		{
			mVEHHashRegionEnd.resolve(iRef++->refRVA);
			mVEHHashRegionStart.resolve(iRef++->refRVA);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		}

		// some weird hashing logic, the hash result is not actually used anywhere...
		if (index == 3 || index == 7 || index == 12 || index == 13 || index == 15)
		{
			ensure(mSectionText.contains(iRef++->refRVA));
			ensure(mSectionText.contains(iRef++->refRVA));
		}

		// index-specific field access
		static size_t perIndexFieldOffsets[] = {
			fieldOffset(&BootstrapStartState::vehVal1),
			fieldOffset(&BootstrapStartState::vehVal2),
			0,
			fieldOffset(&BootstrapStartState::vehVal4),
			fieldOffset(&BootstrapStartState::vehVal1),
			fieldOffset(&BootstrapStartState::vehVal6),
			0,
			fieldOffset(&BootstrapStartState::vehVal2),
			fieldOffset(&BootstrapStartState::vehVal9),
			0,
			fieldOffset(&BootstrapStartState::vehVal11),
			0,
			0,
			0,
			0
		};
		auto fieldOffset = perIndexFieldOffsets[index - 1];
		if (fieldOffset)
			ensure(iRef++->refRVA == mBSS.address() + fieldOffset);

		// the main function that decrypts obfuscate()
		if (index == 14)
		{
			// TODO: this needs full constant propagation logic, both for base RVA and polynomial constants
			// TODO: this actually does need to init obfuscate RVA, this is the main reason we're doing all this...
			ensure(mSectionText.contains(iRef++->refRVA)); // after adjustment: base RVA containing encrypted versions of obfuscate
			ensure(mSectionText.contains(iRef++->refRVA)); // after adjustment: RVA of obfuscate
			ensure(iRef++->refRVA == 0); // imagebase used for VA->RVA conversion...
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::xorredSectionMapping);
			ensure(mSectionRData.contains(iRef++->refRVA)); // gCodeSection.ptr
			ensure(mSectionRData.contains(iRef++->refRVA)); // gCodeSection.size
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::xorredSectionMapping);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::vehDecryptionDone); // TODO: store constant?..
			if (mSectionText.contains(iRef->refRVA))
				++iRef; // sometimes compiler might reload address of obfuscate function here...
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::xorConstants);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::obfuscateFunctionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::obfuscateUnk);
		}

		// match epilogue
		ensure(iRef++->refRVA == numCallsRVA);
		matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		matchDataFieldRef(vehSub, *iRef++, mXorVEHLastExcInfo.field());
		mVEHContinuationFail.resolve(iRef++->refRVA);
		matchDataFieldRef(vehSub, *iRef++, mXorVEHLastExcInfo.field());
		matchDataFieldRef(vehSub, *iRef++, mXorVEHRetval.field());
		ensure(iRef++->refRVA == numCallsRVA);

		ensure(iRef == vehSub.refs().end());
	}

	template<typename... Fields>
	FunctionInfo& processWrapperFunc(rva_t wrapperRVA, const std::string& name, Fields&&... dataRefs)
	{
		auto& wrapper = mFuncs.process(wrapperRVA, name);
		matchDataFieldRefs(wrapper, std::forward<Fields>(dataRefs)...);
		ResolvedAddress implAddr;
		matchTextReferences(wrapper, implAddr);

		return mFuncs.process(implAddr.address(), name + "Impl");
	}

	template<typename... R>
	void matchTextReferences(const FunctionInfo& func, R&... refs)
	{
		auto range = func.refsToSection(mSectionText);
		auto it = range.begin();
		(refs.resolve(it++->refRVA), ...);
		ensure(it == range.end());
	}

	template<typename... R>
	void matchNonCallTextReferences(const FunctionInfo& func, R&... refs)
	{
		auto range = func.refsToSection(mSectionText) | std::ranges::views::filter([](const auto& ref) { return ref.type != FunctionInfo::ReferenceType::Call; });
		auto it = range.begin();
		(refs.resolve(it++->refRVA), ...);
		ensure(it == range.end());
	}

	// match all .data references in a function to a sequence of fields of globals
	template<typename... Fields>
	void matchDataFieldRefs(const FunctionInfo& func, Fields&&... fields)
	{
		auto range = func.refsToSection(mSectionData);
		auto it = range.begin();
		(matchDataFieldRef(func, *it++, fields), ...);
		ensure(it == range.end());
	}

	template<typename Field> void matchDataFieldRef(const FunctionInfo& func, const FunctionInfo::Reference& ref, Field&& field)
	{
		auto offset = fieldOffset(field);
		ensure(ref.refRVA >= mSectionData.begin + offset);
		fieldResolver(field).resolve(ref.refRVA - offset);
	}

	template<typename C, typename T> void matchDataFieldRef(const FunctionInfo& func, const FunctionInfo::Reference& ref, XorredField<T, C>& field)
	{
		matchDataFieldRef(func, ref, field.field());
		field.resolve(mBinary, func, ref);
	}

	template<typename T> ResolvedGlobalAddress<BootstrapStartState>& fieldResolver(T (BootstrapStartState::*)) { return mBSS; }
	template<typename T> ResolvedGlobalAddress<AntitamperStaticState>& fieldResolver(T (AntitamperStaticState::*)) { return mASS; }

	void dumpRefs(const FunctionInfo& func)
	{
		for (auto& ref : func.refs())
		{
			if (ref.refRVA >= mBSS.address() && ref.refRVA < mBSS.address() + sizeof(BootstrapStartState))
				std::println("> BSS + 0x{:X}", ref.refRVA - mBSS.address());
			else if (ref.refRVA >= mASS.address() && ref.refRVA < mASS.address() + sizeof(AntitamperStaticState))
				std::println("> ASS + 0x{:X}", ref.refRVA - mASS.address());
			else
				std::println("> {}", mBinary.formatRVA(ref.refRVA));
		}
	}

private:
	PEBinary mBinary;
	const PEBinary::Section& mSectionText;
	const PEBinary::Section& mSectionRData;
	const PEBinary::Section& mSectionData;
	FunctionTable mFuncs;

	ResolvedGlobalAddress<BootstrapStartState> mBSS;
	ResolvedGlobalAddress<AntitamperStaticState> mASS;
	XorredField<u64, BootstrapStartState> mXorRtlAddVectoredExceptionHandler{ &BootstrapStartState::xorredRtlAddVectoredExceptionHandler, "RtlAddVectoredExceptionHandler" };
	XorredField<u64, BootstrapStartState> mXorCloseHandle{ &BootstrapStartState::xorredCloseHandle, "CloseHandle" };
	XorredField<u64, BootstrapStartState> mXorVirtualAlloc{ &BootstrapStartState::xorredVirtualAlloc, "VirtualAlloc" };
	XorredField<u64, BootstrapStartState> mXorNtCreateSection{ &BootstrapStartState::xorredNtCreateSection, "NtCreateSection" };
	XorredField<u64, BootstrapStartState> mXorMapViewOfFileEx{ &BootstrapStartState::xorredMapViewOfFileEx, "MapViewOfFileEx" };
	XorredField<u64, BootstrapStartState> mXorVirtualProtect{ &BootstrapStartState::xorredVirtualProtect, "VirtualProtect" };
	XorredField<u64, BootstrapStartState> mXorUnmapViewOfFile{ &BootstrapStartState::xorredUnmapViewOfFile, "UnmapViewOfFile" };
	XorredField<u64, BootstrapStartState> mXorRemoveVectoredExceptionHandler{ &BootstrapStartState::xorredRemoveVectoredExceptionHandler, "RemoveVectoredExceptionHandler" };
	XorredField<u32, BootstrapStartState> mXorVEHRetval{ &BootstrapStartState::vehXorredRetval, "VEHRetval" };
	XorredField<u64, BootstrapStartState> mXorVEHLastExcInfo{ &BootstrapStartState::vehXorredLastExceptionInfo, "VEHLastExcInfo" };

	// special .text references
	ResolvedAddress mTLSDecode;
	ResolvedAddress mTLSFixup;
	ResolvedAddress mTLSRuntime;
	ResolvedAddress mVEHMain;
	ResolvedAddress mVEHHashRegionStart;
	ResolvedAddress mVEHHashRegionEnd;
	ResolvedAddress mVEHContinuationFail;
};

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::println("File name expected");
		return 1;
	}

	try
	{
		SC2Binary bin(argv[1]);
		return 0;
	}
	catch (std::exception& e)
	{
		std::println("Error: {}", e.what());
		return 2;
	}
}
