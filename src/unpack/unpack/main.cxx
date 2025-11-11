#include <common/win_headers.h>
#include <capstone/capstone.h>

import std;
import common;
import unpack.pe_binary;
import unpack.function;
import unpack.known_structs;

import unpack.patcher;
import unpack.function_table;
import unpack.analysis.simple_refs;

template<typename T, typename F> constexpr size_t fieldOffset(F (T::*f))
{
	auto& pm = static_cast<T*>(nullptr)->*f;
	return reinterpret_cast<size_t>(&pm);
}

// executable sections that we care about
enum class Section { Text, RData, Data };

// address of some entity in the executable
// initially it's location is unknown; when we discover first reference, we save the RVA - and then validate that all other references match
template<Section S> class ResolvedAddress
{
public:
	static constexpr Section Section = S;

	bool resolved() const { return mRVA; }
	auto address() const { ensure(resolved()); return mRVA; }

	void resolve(rva_t rva, PEBinary& bin)
	{
		if (!mRVA)
		{
			ensure(bin.sections()[static_cast<int>(S)].contains(rva));
			mRVA = rva;
		}
		else
		{
			ensure(mRVA == rva);
		}
	}

private:
	rva_t mRVA = 0; // 0 until discovered
};

// address of a global structure; resolved by field accesses
template<typename T, Section S> class ResolvedGlobalAddress : public ResolvedAddress<S>
{
public:
	T* access(PEBinary& bin) const { return bin.structAtRVA<T>(this->address()); }
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

// TODO: RTTI?
class SC2Binary
{
public:
	SC2Binary(const std::string& path, bool applyRuntimePatches)
		: mApplyRuntimePatches(applyRuntimePatches)
		, mBinary(path.c_str())
		, mPatcher(mBinary, true, applyRuntimePatches)
		, mFuncs(mBinary)
		, mFuncTable(mBinary, sectionText(), mPatcher)
	{
		ensure(sectionText().name == ".text");
		ensure(sectionRData().name == ".rdata");
		ensure(sectionData().name == ".data");

		// note on relocs: SC2 binary has 0 relocs in .text section, which makes sense (there's stuff in vtables etc that needs to be relocated, code uses rip relative addressing modes everywhere...)
		// this means we can completely skip emulating all the manual relocation logic in decompressor
		for (auto reloc : mBinary.relocRVAs())
			ensure(!sectionText().contains(reloc));

		processBootstrapStart();
		processTLSCallbacks();

		mBinary.save((path + "_fixed").c_str());
	}

private:
	// process fallback start function
	void processBootstrapStart()
	{
		// note: bootstrap function is noreturn, and the very last block containing 'normal' return is unreachable
		auto& func = mFuncTable.analyze(mBinary.entryPoint(), "bootstrapStart", [](auto& analyzer, rva_t start, rva_t limit) {
			analyzer.start(start, limit);
			analyzer.scheduleAndAnalyze(start);
			analyzer.scheduleAndAnalyze(analyzer.currentBlocks().back().end);
			return analyzer.finish();
		});

		// we don't care about rdata refs here, these are error messages
		resolveRefs(analysis::getSimpleRefs(func.instructions) | std::views::filter([&](const auto& r) { return !sectionRData().contains(r.ref); }),
			&BootstrapStartState::stage);
		ensure(mBSS.address() - sectionData().begin == 0x60); // not sure what's there before it and how likely is it to change...
	}

	// *** start legacy ***
	// process TLS callbacks that do the actual decoding
	void processTLSCallbacks()
	{
		// note: tls directory is in .rdata, just preceding RTTI data...
		ensure(mBinary.tlsCallbackRVAs().size() == 1);
		auto& func = mFuncTable.analyze(mBinary.tlsCallbackRVAs().front(), "bootstrapTLSInitial");

		auto& tlsInitial = mFuncs.process(mBinary.tlsCallbackRVAs().front(), "bootstrapTLSInitial");
		matchDataFieldRefs(tlsInitial,
			&BootstrapStartState::stage,
			&AntitamperStaticState::xorConstants,
			&AntitamperStaticState::supportSSE, // processor caps flags
			&AntitamperStaticState::pageHashUsesAVX2); // last flag
		matchTextReferences(tlsInitial, mTLSRuntime, mTLSDecode, mTLSFixup);
		// note: RTTI between tls directory and antidebug static ?..

		if (mApplyRuntimePatches)
		{
			// keep xor constants as zeros: skip the loop
			auto xorConstantInitRef = tlsInitial.findRefTo(mASS.address() + fieldOffset(&AntitamperStaticState::xorConstants));
			//patchSkipLoop(tlsInitial, xorConstantInitRef->insnRVA);
			auto xorConstantInitBlock = tlsInitial.findBlock(xorConstantInitRef->insnRVA);
			auto xorConstantPreBlock = tlsInitial.findBlock(xorConstantInitBlock->begin - 1);
			ensure(xorConstantPreBlock && xorConstantPreBlock->successors.size() == 2 && xorConstantPreBlock->successors[0].rva == xorConstantInitBlock->begin);
			ensure(!xorConstantPreBlock->instructions.empty());
			patchJumpToUnconditional(xorConstantPreBlock->instructions.back().rva);
		}

		processTLSDecode();
		processTLSFixup();
		// TODO: queue up tlsruntime & realentrypoint, then queue up everything recursively

		if (mApplyRuntimePatches) // TODO: do *not* do this for runtime, at least unless patching the tls fixup...
		{
			// patch the entrypoint to the real one
			auto realEntryPoint = mBSS.access(mBinary)->encryptedInfo.rvaEntryPoint;
			mBinary.peHeader().OptionalHeader.AddressOfEntryPoint = realEntryPoint;
		}
	}

	// main decoding tls callback
	void processTLSDecode()
	{
		auto& tlsDecodeImpl = processWrapperFunc(mTLSDecode.address(), "bootstrapTLSDecode", &BootstrapStartState::stage);

		auto iRef = tlsDecodeImpl.refs().begin();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		auto imagebaseReg = matchImagebaseLoad(tlsDecodeImpl, *iRef++); // this is kinda bad, this is used to fill relocationsStraddlingPageBoundary
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::relocationsStraddlingPageBoundaryCount);
		processVEH(iRef++->refRVA);
		if (iRef->refRVA == 0)
			imagebaseReg = matchImagebaseLoad(tlsDecodeImpl, *iRef++); // sucks, used to do forbidden module decoding

		processEmptyFunc(iRef->refRVA, "bootstrapAnyModuleLoaded");
		decodeBootstrapInfo(tlsDecodeImpl, imagebaseReg, iRef++->insnRVA);

		ResolvedAddress<Section::Text> remapSections, remapSectionsEnd;
		remapSectionsEnd.resolve(iRef++->refRVA, mBinary);
		remapSections.resolve(iRef++->refRVA, mBinary);
		ensure(remapSectionsEnd.address() > remapSections.address());
		processEmptyFunc(remapSections.address(), "bootstrapRemapSections");

		matchDataFieldRef(tlsDecodeImpl, *iRef, mXorVirtualAlloc.field());
		if (mApplyRuntimePatches)
		{
			// patch out random-fill of allocated antitamper state
			patchSkipNextLoop(tlsDecodeImpl, iRef->insnRVA);
		}
		++iRef;

		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorNtCreateSection.field());
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorMapViewOfFileEx.field());
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorVirtualProtect.field());
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorUnmapViewOfFile.field());
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorMapViewOfFileEx.field());
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorVirtualProtect.field());
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::sections));
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &BootstrapStartState::stage);
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::textRVA));
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::textSize));
		matchRDataFieldRef(tlsDecodeImpl, *iRef++, &MappedRegions::textSection);
		matchRDataFieldRef(tlsDecodeImpl, *iRef++, &MappedRegions::executableRegion);
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::rdataRVA));
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::rdataSize));
		matchRDataFieldRef(tlsDecodeImpl, *iRef++, &MappedRegions::rdataSection);

		ensure(iRef->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::textRVA));
		//if (mApplyRuntimePatches)
		//	patchSkipNextLoop(tlsDecodeImpl, iRef->insnRVA);
		++iRef;

		ensure(iRef->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::rdataRVA));
		//if (mApplyRuntimePatches)
		//	patchSkipNextLoop(tlsDecodeImpl, iRef->insnRVA);
		++iRef;

		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::writableSectionMapping);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::vehDecryptionDone);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::vehDecryptionFailed);
		ensure(sectionText().contains(iRef++->refRVA)); // ??? some sort of failure handler, looks encrypted, or just junk?..
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::vehDecryptionDone);
		mObfuscate.resolve(iRef++->refRVA, mBinary);
		imagebaseReg = matchImagebaseLoad(tlsDecodeImpl, *iRef++); // used for reading xor constants
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorVirtualAlloc.field());

		// the next ref is used to encode num page hashes
		// TODO: this is very sus tbh, might as well use access via reg or something, but seems to work
		ensure(iRef->refRVA >= mASS.address() + fieldOffset(&AntitamperStaticState::xorConstants) && iRef->refRVA < mASS.address() + fieldOffset(&AntitamperStaticState::delayedCrashEncodedState));
		if (mApplyRuntimePatches)
		{
			// preceeded by div reg32; we want to patch it to 'mov reg, 1', but we need more space...
			auto iBlock = ensure(tlsDecodeImpl.findBlock(iRef->insnRVA));
			auto iIsn = iBlock->findInstruction(iRef->insnRVA);
			--iIsn;
			ensure(iIsn->mnem == X86_INS_DIV && iIsn->opcount == 1 && iIsn->ops[0].type == OperandType::Reg);
			auto [numPagesReg, numPagesSize] = Register::toOffsetSize(iIsn->ops[0].reg);
			// preceeded by mov reg64, ...
			--iIsn;
			ensure(iIsn->mnem == X86_INS_MOV && iIsn->opcount == 2 && iIsn->ops[0].type == OperandType::Reg);
			auto [preceedingReg, preceedingSize] = Register::toOffsetSize(iIsn->ops[0].reg);
			ensure(numPagesReg == preceedingReg && numPagesSize == 4 && preceedingSize == 8);
			numPagesReg >>= 3;
			ensure(numPagesReg < 16);
			const unsigned char movPatch[] = { static_cast<u8>(0x40 | (numPagesReg < 8 ? 0 : 1)), static_cast<u8>(0xB8 | (numPagesReg & 7)), 0x01, 0x00, 0x00, 0x00 }; // always add rex for simplicity
			patch(iIsn->rva, iRef->insnRVA - iIsn->rva, std::span(movPatch));
		}
		iRef++;

		// different versions of executable reload imagebase, obfuscate function or xor constnt from now on at random places; skip that
		// also skip random .rdata references (used by avx hashing)
		auto skipUninteresting = [&]() {
			while (iRef->refRVA == 0 || iRef->refRVA == mObfuscate.address() ||
				iRef->refRVA >= mASS.address() + fieldOffset(&AntitamperStaticState::xorConstants) && iRef->refRVA < mASS.address() + fieldOffset(&AntitamperStaticState::delayedCrashEncodedState) ||
				sectionRData().contains(iRef->refRVA))
			{
				++iRef;
			}
		};
		skipUninteresting();

		processInitADS(iRef++->refRVA);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::bootstrapVEHHandle); // remove veh handler
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &BootstrapStartState::stage); // enter stage F
		processEmptyFunc(iRef++->refRVA, "bootstrapGetKernel32APIs");
		skipUninteresting();
		processDecryptImports(iRef++->refRVA);

		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::pageRegions));
		mUnencryptedStart.resolve(iRef++->refRVA, mBinary);
		mUnencryptedEnd.resolve(iRef++->refRVA, mBinary);
		ensure(mUnencryptedStart.address() == sectionText().begin && sectionText().contains(mUnencryptedEnd.address()));
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &BootstrapStartState::stage); // enter stage D

		skipUninteresting();
		processDecryptPage(iRef++->refRVA, "Var3");
		skipUninteresting();
		auto decryptPage12 = iRef++->refRVA;
		processDecryptPage(decryptPage12, "Var12");
		skipUninteresting();
		ensure(iRef++->refRVA == decryptPage12);
		skipUninteresting();
		processDecryptPage(iRef++->refRVA, "Var0");
		mUnencryptedEnd.resolve(iRef++->refRVA, mBinary);
		mUnencryptedStart.resolve(iRef++->refRVA, mBinary);
		decodePages();
		processLeafFunc(iRef++->refRVA, "bootstrapProcessNewThread");

		// copy expected remapped section state
		mRemappedSegmentState.resolve(iRef++->refRVA, mBinary);
		mRemappedSegmentCount.resolve(iRef++->refRVA, mBinary);
		ensure(sectionText().contains(mRemappedSegmentState.address()) && sectionText().contains(mRemappedSegmentCount.address()));
		// TODO: nop out next loop, which random-fills the state array
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::sections));
		skipUninteresting();

		// and then hash it (state and count)
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::supportSSE);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::pageHashUsesAVX2);
		skipUninteresting();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::supportSSE);
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::pageHashUsesAVX2);
		skipUninteresting();

		// code that sets up two mappings to the same random region in bootstrap code
		ensure(iRef++->refRVA == tlsDecodeImpl.startRVA());
		skipUninteresting();

		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorCloseHandle.field()); // close mapping
		// TODO: nop out PE header fuckup
		matchDataFieldRef(tlsDecodeImpl, *iRef++, mXorVirtualProtect.field()); // close mapping
		matchDataFieldRef(tlsDecodeImpl, *iRef++, &AntitamperStaticState::tlsDecryptionDone);
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
			&AntitamperStaticState::writableSectionMapping,
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
			&AntitamperStaticState::writableSectionMapping,
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
		processEmptyFunc(mVEHContinuationFail.address(), "bootstrapVEHContinuationFail");

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

		// bootstrap region rehash logic is repeated in a few functions
		if (index == 1 || index == 2 || index == 5 || index == 8 || index == 10)
		{
			mVEHHashRegionEnd.resolve(iRef++->refRVA, mBinary);
			mVEHHashRegionStart.resolve(iRef++->refRVA, mBinary);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		}

		// some weird hashing logic, the hash result is not actually used anywhere...
		if (index == 3 || index == 7 || index == 12 || index == 13 || index == 15)
		{
			ensure(sectionText().contains(iRef++->refRVA));
			ensure(sectionText().contains(iRef++->refRVA));
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
			// TODO: do full constant propagation logic, both for base RVA and polynomial constants
			ensure(sectionText().contains(iRef++->refRVA)); // after adjustment: base RVA containing encrypted versions of obfuscate
			auto decodeLoopAddr = iRef->insnRVA;
			mObfuscate.resolve(iRef++->refRVA, mBinary); // RVA of obfuscate - note that it might be offset by a constant!
			ensure(iRef++->refRVA == 0); // imagebase used for VA->RVA conversion...
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::writableSectionMapping);
			ensure(sectionRData().contains(iRef++->refRVA)); // gCodeSection.ptr
			ensure(sectionRData().contains(iRef++->refRVA)); // gCodeSection.size
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::writableSectionMapping);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::vehDecryptionDone); // TODO: store constant?..
			if (sectionText().contains(iRef->refRVA))
			{
				// sometimes compiler might reload address of obfuscate function here, and now it seems to be done directly without adjustment...
				mObfuscate = {};
				mObfuscate.resolve(iRef++->refRVA, mBinary);
			}
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::xorConstants);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::obfuscateFunctionHash);
			matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::obfuscateUnk);

			if (mApplyRuntimePatches)
			{
				// skip decoding loop
				auto decodeDestBlock = vehSub.findBlock(decodeLoopAddr);
				ensure(decodeDestBlock && decodeDestBlock->successors.size() == 2 && !decodeDestBlock->instructions.empty());
				patchJumpToUnconditional(decodeDestBlock->instructions.back().rva);

				// and write out the implementation of obfuscate
				// we have two options here - a no-op, or one that would replace constants with zeros
				const unsigned char obfuscateImpl[] = {
					0x31, 0xC0, // xor eax, eax
					0x48, 0x89, 0x01, // mov [rcx], rax
					0x48, 0x89, 0x02, // mov [rdx], rax
					0xC3 // ret
				};
				patch(mObfuscate.address(), 0x400, std::span(obfuscateImpl));
			}
		}

		// match epilogue
		ensure(iRef++->refRVA == numCallsRVA);
		matchDataFieldRef(vehSub, *iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		matchDataFieldRef(vehSub, *iRef++, mXorVEHLastExcInfo.field());
		mVEHContinuationFail.resolve(iRef++->refRVA, mBinary);
		matchDataFieldRef(vehSub, *iRef++, mXorVEHLastExcInfo.field());
		matchDataFieldRef(vehSub, *iRef++, mXorVEHRetval.field());
		ensure(iRef++->refRVA == numCallsRVA);

		ensure(iRef == vehSub.refs().end());
	}

	void processInitADS(rva_t rva)
	{
		ensure(sectionText().contains(rva));
		auto& func = mFuncs.process(rva, "bootstrapInitAntitamperDynamicState");
		matchTextReferences(func, mObfuscate, mTLSRuntime);
		// data refs are not interesting, to xor constants and then to a bunch of functions
		// note: there's some reference to beyond import table (in .rdata), what's this?..
	}

	void processDecryptImports(rva_t rva)
	{
		ensure(sectionText().contains(rva));
		auto& func = mFuncs.process(rva, "bootstrapDecryptImports");

		auto iRef = func.refs().begin();
		mShuffle.resolve(iRef++->refRVA, mBinary);
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::failedImportLibName);
		mShuffle.resolve(iRef++->refRVA, mBinary);
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::failedImportFuncName);
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::failedImportLibName);
		mImportFail.resolve(iRef++->refRVA, mBinary);
		ensure(iRef == func.refs().end());

		ensure(sectionRData().contains(mShuffle.address()));
		ensure(sectionText().contains(mImportFail.address()));

		decodeImports();

		if (mApplyRuntimePatches)
		{
			// just replace the entire function with 'return true'
			const unsigned char replacement[] = {
				0xB0, 0x01, // mov al, 1
				0xC3, // ret
			};
			patch(rva, func.endRVA() - func.startRVA(), std::span(replacement));
		}
	}

	void processDecryptPage(rva_t rva, std::string_view tag)
	{
		// nothing interesting in any of these...
		auto& func = processLeafFunc(rva, std::format("bootstrapDecryptPage{}", tag));

		// TODO: patch out decode loop
		if (mApplyRuntimePatches)
		{
			auto fnvWrite = std::ranges::find_if(func.refs(), [&](const auto& ref) { return ref.refRVA == mASS.address() + fieldOffset(&AntitamperStaticState::prevDecryptedPageHash) && ref.type == FunctionInfo::ReferenceType::Write; });
			ensure(fnvWrite != func.refs().end());
			auto iBlock = func.blocks().findNext(fnvWrite->insnRVA);
			// first loop before write is hash calculation
			while (std::ranges::none_of(iBlock->successors, [&](const auto& succ) { return succ.rva == iBlock->begin; }))
				--iBlock;
			ensure(std::ranges::any_of(iBlock->instructions, [](const auto& isn) { return isn.mnem == X86_INS_IMUL; }));
			--iBlock;
			// second loop before write is actual hashing loop
			while (std::ranges::none_of(iBlock->successors, [&](const auto& succ) { return succ.rva == iBlock->begin; }))
				--iBlock;
			patchSkipOuterLoop(func, iBlock->begin);
		}
	}

	void processTLSFixup()
	{
		auto& func = processWrapperFunc(mTLSFixup.address(), "bootstrapTLSFixup", &BootstrapStartState::stage);

		auto iRef = func.refs().begin();
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::dynState);
		mObfuscate.resolve(iRef++->refRVA, mBinary);
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::xorConstants);
		matchDataFieldRef(func, *iRef++, &AntitamperStaticState::tlsDecryptionDone);
		processEmptyFunc(iRef++->refRVA, "bootstrapTLSDummy"); // replace 2nd & 3rd tls callbacks with dummy func
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::rvaEntryPoint)); // read real entrypoint
		ensure(iRef++->refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo) + fieldOffset(&BootstrapInfo::rvaEntryPoint)); // patch with random stuff (TODO: nop out the loop)
		// the next code overwrites the entire bootstrap section with random stuff; TODO reconsider...
		mVEHHashRegionStart.resolve(iRef++->refRVA, mBinary);
		mVEHHashRegionEnd.resolve(iRef++->refRVA, mBinary);
		ensure(iRef++->refRVA == mBinary.entryPoint()); // patching out the entrypoint to jump to real one
		ensure(iRef == func.refs().end());
	}

	void processEmptyFunc(rva_t rva, std::string_view name)
	{
		ensure(sectionText().contains(rva));
		auto& func = mFuncs.process(rva, name);
		ensure(func.refs().empty());
	}

	FunctionInfo& processLeafFunc(rva_t rva, std::string_view name)
	{
		ensure(sectionText().contains(rva));
		auto& func = mFuncs.process(rva, name);
		ensure(std::ranges::all_of(func.refsToSection(sectionText()), [&](const auto& ref) { return ref.refRVA == mObfuscate.address(); }));
		return func;
	}

	template<typename... Fields>
	FunctionInfo& processWrapperFunc(rva_t wrapperRVA, const std::string& name, Fields&&... dataRefs)
	{
		auto& wrapper = mFuncs.process(wrapperRVA, name);
		matchDataFieldRefs(wrapper, std::forward<Fields>(dataRefs)...);
		ResolvedAddress<Section::Text> implAddr;
		matchTextReferences(wrapper, implAddr);

		return mFuncs.process(implAddr.address(), name + "Impl");
	}

	// decode bootstrap info structure
	// TODO: we can resolve shuffle reference while analyzing decrypt imports, and do this after bootstrap analysis is complete before applying runtime patches
	void decodeBootstrapInfo(const FunctionInfo& func, x86_reg imagebaseReg, rva_t lookupStartRVA)
	{
		auto shuffleRef = findNextIndirectReference(func, imagebaseReg, lookupStartRVA);
		ensure(sectionRData().contains(shuffleRef.refRVA));
		mShuffle.resolve(shuffleRef.refRVA, mBinary);
		auto shuffle = &mBinary.bytes()[shuffleRef.refRVA];

		auto infoRef = findNextIndirectReference(func, imagebaseReg, shuffleRef.insnRVA);
		ensure(infoRef.refRVA == mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo));
		auto info = &mBinary.bytes()[infoRef.refRVA];

		unsigned char buffer[256];
		for (int i = 0; i < sizeof buffer; ++i)
			buffer[i] = i;
		unsigned char swap = 0;
		for (int i = 0; i < sizeof buffer; ++i)
		{
			swap += buffer[i] + shuffle[i % 16];
			std::swap(buffer[i], buffer[swap]);
		}

		unsigned char j = 0;
		swap = 0;
		for (int i = 0; i < sizeof BootstrapInfo; ++i)
		{
			auto v = buffer[++j];
			info[i] ^= v;
			swap += v;
			buffer[j] = buffer[swap];
			buffer[swap] = v;
		}

		if (mApplyRuntimePatches)
		{
			patchSkipOuterLoop(func, shuffleRef.insnRVA);
			patchSkipOuterLoop(func, infoRef.insnRVA);
		}
	}

	void decodeImports()
	{
		int shuffleIndex = 0;
		auto shuffle = &mBinary.bytes()[mShuffle.address()];
		auto simpleDecode = [&](auto& value) {
			auto p = reinterpret_cast<unsigned char*>(&value);
			for (int i = 0; i < sizeof value; ++i)
				*p++ ^= shuffle[shuffleIndex++ % 506];
		};
		auto decodeString = [&](char* ptr)
		{
			for (; ; ++shuffleIndex, ++ptr)
			{
				*ptr ^= shuffle[shuffleIndex % 506];
				if (!*ptr)
					return;
			}
		};

		u32 importDirectoryTableOffset = mBinary.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		simpleDecode(importDirectoryTableOffset);
		ensure(sectionRData().contains(importDirectoryTableOffset));

		SimpleRangeMap<rva_t> iat;

		int numDescriptors = 0;
		for (auto entry = mBinary.structAtRVA<IMAGE_IMPORT_DESCRIPTOR>(importDirectoryTableOffset); entry->Characteristics; ++entry, ++numDescriptors)
		{
			simpleDecode(*entry);
			ensure(sectionRData().contains(entry->OriginalFirstThunk) && sectionRData().contains(entry->Name) && sectionRData().contains(entry->FirstThunk));

			auto libName = mBinary.structAtRVA<char>(entry->Name);
			decodeString(libName);
			//std::println("> Importing {}, IAT @ {:X}", libName, entry->FirstThunk);

			int numImports = 0;
			auto curIAT = mBinary.structAtRVA<u64>(entry->FirstThunk);
			for (auto curImport = mBinary.structAtRVA<u64>(entry->OriginalFirstThunk); *curImport; ++curImport, ++curIAT, ++numImports)
			{
				simpleDecode(*curImport);
				ensure(*curIAT == 0);
				*curIAT = *curImport;
				if ((*curImport >> 63) == 0)
				{
					// import by name
					ensure(sectionRData().contains(*curImport));
					auto funcName = mBinary.structAtRVA<char>(*curImport + 2);
					decodeString(funcName);
					//std::println(">> Function {}", funcName);
				}
				else
				{
					// import by ordinal
					//std::println(">> Function #{}", *curImport ^ (1ull << 63));
				}
			}
			ensure(*curIAT == 0);

			rva_t entryStart = entry->FirstThunk;
			iat.insert({ entryStart, entryStart + 8 * (numImports + 1) });
		}

		for (int i = 1; i < iat.size(); ++i)
			ensure(iat[i - 1].end == iat[i].begin);
		u32 iatRVA = iat[0].begin, iatRVAEnd = iat.back().end;
		mBinary.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = { importDirectoryTableOffset, sizeof(IMAGE_IMPORT_DESCRIPTOR) * (numDescriptors + 1) };
		mBinary.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = { iatRVA, iatRVAEnd - iatRVA };
	}

	void decodePages()
	{
		auto& info = mBSS.access(mBinary)->encryptedInfo.pageRegions;
		ensure(info[0].rva == sectionText().begin && info[0].size == sectionText().end - sectionText().begin);
		ensure(info[1].rva == 0); // note: second region would use slightly different decryption function, i didn't reverse it

		i64 prevPageFNV1 = 0;
		auto prevPageFNV1Ptr = reinterpret_cast<unsigned char*>(&prevPageFNV1);
		for (auto pageStart = info[0].rva; pageStart < info[0].rva + info[0].size; pageStart += 4096)
		{
			if (pageStart >= mUnencryptedStart.address() && pageStart < mUnencryptedEnd.address())
				continue;
			// note: we assume there are no relocs inside .text, meaning no relocs straddling page boundaries, meaning we don't need to bother...

			auto pageIndex = pageStart / 4096;
			auto shufflePage = pageIndex % 166;
			auto shuffle = mBinary.structAtRVA<unsigned char>(mShuffle.address());

			unsigned char keyBuffer[506];
			for (int i = 0; i < sizeof keyBuffer; ++i)
				keyBuffer[i] = shuffle[506 * shufflePage + i] ^ prevPageFNV1Ptr[i & 7];

			unsigned char shuffleBuffer[256];
			for (int i = 0; i < sizeof shuffleBuffer; ++i)
				shuffleBuffer[i] = i;
			unsigned char swap = 0;
			for (int i = 0; i < sizeof shuffleBuffer; ++i)
			{
				swap += shuffleBuffer[i] + keyBuffer[i];
				std::swap(shuffleBuffer[i], shuffleBuffer[swap]);
			}

			unsigned char idx = 0;
			swap = 0;
			auto data = mBinary.structAtRVA<unsigned char>(pageStart);
			prevPageFNV1 = 0xCBF29CE484222325ll;
			for (int i = 0; i < 4096; ++i, ++data)
			{
				auto v = shuffleBuffer[++idx];
				*data ^= v;
				swap += v;
				std::swap(shuffleBuffer[idx], shuffleBuffer[swap]);

				prevPageFNV1 ^= *data;
				prevPageFNV1 *= 0x100000001B3ll;
			}
		}
	}

	template<typename... R>
	void matchTextReferences(const FunctionInfo& func, R&... refs)
	{
		auto range = func.refsToSection(sectionText());
		auto it = range.begin();
		(refs.resolve(it++->refRVA, mBinary), ...);
		ensure(it == range.end());
	}

	template<typename... R>
	void matchNonCallTextReferences(const FunctionInfo& func, R&... refs)
	{
		auto range = func.refsToSection(sectionText()) | std::ranges::views::filter([](const auto& ref) { return ref.type != FunctionInfo::ReferenceType::Call; });
		auto it = range.begin();
		(refs.resolve(it++->refRVA, mBinary), ...);
		ensure(it == range.end());
	}

	// match all .data references in a function to a sequence of fields of globals
	template<typename... Fields>
	void matchDataFieldRefs(const FunctionInfo& func, Fields&&... fields)
	{
		auto range = func.refsToSection(sectionData());
		auto it = range.begin();
		(matchDataFieldRef(func, *it++, fields), ...);
		ensure(it == range.end());
	}

	template<typename Field> void matchDataFieldRef(const FunctionInfo& func, const FunctionInfo::Reference& ref, Field&& field)
	{
		fieldResolver(field).resolve(ref.refRVA - fieldOffset(field), mBinary);
	}

	template<typename C, typename T> void matchDataFieldRef(const FunctionInfo& func, const FunctionInfo::Reference& ref, XorredField<T, C>& field)
	{
		matchDataFieldRef(func, ref, field.field());
		field.resolve(mBinary, func, ref);
	}

	template<typename Field> void matchRDataFieldRef(const FunctionInfo& func, const FunctionInfo::Reference& ref, Field&& field)
	{
		fieldResolver(field).resolve(ref.refRVA - fieldOffset(field), mBinary);
	}

	// match lea reg, imagebase ref
	x86_reg matchImagebaseLoad(const FunctionInfo& func, const FunctionInfo::Reference& ref)
	{
		ensure(ref.refRVA == 0);
		auto block = ensure(func.findBlock(ref.insnRVA));
		auto it = block->findInstruction(ref.insnRVA);
		ensure(it != block->instructions.end());
		ensure(it->mnem == X86_INS_LEA && it->opcount == 2 && it->ops[0].type == OperandType::Reg);
		return it->ops[0].reg;
	}

	FunctionInfo::Reference findNextIndirectReference(const FunctionInfo& func, x86_reg imagebaseReg, rva_t startFrom)
	{
		auto iBlock = func.blocks().findNext(startFrom);
		if (iBlock != func.blocks().begin() && (iBlock - 1)->contains(startFrom))
			--iBlock;
		auto iIsn = iBlock->findInstruction(startFrom);
		if (iIsn != iBlock->instructions.end())
			++iIsn;
		while (true)
		{
			while (iIsn != iBlock->instructions.end())
			{
				int iMemOp = 0;
				for (; iMemOp < iIsn->opcount; ++iMemOp)
					if (iIsn->ops[iMemOp].type == OperandType::Mem)
						break;
				if (iMemOp < iIsn->opcount && (iIsn->mem.base == imagebaseReg || iIsn->mem.index == imagebaseReg && iIsn->mem.scale == 1))
				{
					auto type = iIsn->mnem == X86_INS_LEA && iMemOp != 0 ? FunctionInfo::ReferenceType::Address : iIsn->ops[iMemOp].access == CS_AC_READ ? FunctionInfo::ReferenceType::Read : FunctionInfo::ReferenceType::Write;
					return { iIsn->rva, static_cast<rva_t>(iIsn->mem.disp), type };
				}
				++iIsn;
			}

			++iBlock;
			if (iBlock == func.blocks().end())
				break;
			iIsn = iBlock->instructions.begin();
		}
		return {};
	}

	template<typename Span>
	void patch(rva_t start, size_t size, Span&& patch)
	{
		ensure(size >= patch.size());
		auto dest = &mBinary.bytes()[start];
		memcpy(dest, patch.data(), patch.size());
		memset(dest + patch.size(), 0x90, size - patch.size());
	}

	void patchSkipOuterLoop(const FunctionInfo& func, rva_t rva)
	{
		auto iBlock = func.blocks().findNext(rva);
		ensure(iBlock != func.blocks().begin());
		--iBlock;
		ensure(iBlock->contains(rva));
		ensure(iBlock->successors.size() == 2 && iBlock->successors[0].rva == iBlock->end && iBlock->successors[1].rva == iBlock->begin);
		// find preceeding block that can jump to loop end
		auto iPrev = iBlock;
		while (iPrev != func.blocks().begin())
		{
			--iPrev;
			if (iPrev->successors.size() == 2 && iPrev->successors[1].rva >= iBlock->end)
			{
				ensure(!iPrev->instructions.empty());
				patchJumpToUnconditional(iPrev->instructions.back().rva);
				return;
			}
		}
		ensure(false);
	}

	void patchSkipNextLoop(const FunctionInfo& func, rva_t rva)
	{
		for (auto iBlock = func.blocks().findNext(rva); iBlock != func.blocks().end(); ++iBlock)
		{
			if (std::ranges::any_of(iBlock->successors, [&](const auto& succ) { return succ.rva <= iBlock->begin; }))
			{
				patchSkipOuterLoop(func, iBlock->begin);
				return;
			}
		}
		ensure(false);
	}

	void patchJumpToUnconditional(rva_t rva)
	{
		auto* address = &mBinary.bytes()[rva];
		if ((address[0] & 0xF0) == 0x70)
		{
			// near
			std::println("Patching short jump at {:X}", rva);
			address[0] = 0xEB;
		}
		else if (address[0] == 0x0F && (address[1] & 0xF0) == 0x80)
		{
			std::println("Patching near jump at {:X}", rva);
			address[0] = 0x90;
			address[1] = 0xE9;
		}
		else
		{
			std::println("Failed to patch jump at {:X}: {:02X}", rva, address[0]);
		}
	}
	// *** end legacy ***

	// new stuff ...
	const PEBinary::Section& section(Section id) { return mBinary.sections()[static_cast<int>(id)]; }
	const PEBinary::Section& sectionText() { return section(Section::Text); }
	const PEBinary::Section& sectionRData() { return section(Section::RData); }
	const PEBinary::Section& sectionData() { return section(Section::Data); }

	template<typename T> auto& fieldResolver(T (BootstrapStartState::*)) { return mBSS; }
	template<typename T> auto& fieldResolver(T (AntitamperStaticState::*)) { return mASS; }
	template<typename T> auto& fieldResolver(T (MappedRegions::*)) { return mMR; }

	void resolveRefs(auto&& refs, auto&&... resolvers)
	{
		auto it = std::ranges::begin(refs);
		auto end = std::ranges::end(refs);
		((ensure(it != end), resolveRef(*it++, std::forward<decltype(resolvers)>(resolvers))), ...);
		ensure(it == end);
	}

	template<typename T, typename R>
	void resolveRef(const analysis::Reference& ref, R (T::*field)) { fieldResolver(field).resolve(ref.ref - fieldOffset(field), mBinary); }

	template<Section S>
	void resolveRef(const analysis::Reference& ref, ResolvedAddress<S>& addr) { addr.resolve(ref.ref, mBinary); }

	void dumpRefs(auto&& refs)
	{
		for (auto& r : refs)
		{
			if (mBSS.resolved() && r.ref >= mBSS.address() && r.ref < mBSS.address() + sizeof(BootstrapStartState))
				std::println("{:X} > BSS + 0x{:X} [{}]", r.ins->rva, r.ref - mBSS.address(), *r.ins);
			else if (mASS.resolved() && r.ref >= mASS.address() && r.ref < mASS.address() + sizeof(AntitamperStaticState))
				std::println("{:X} > ASS + 0x{:X} [{}]", r.ins->rva, r.ref - mASS.address(), *r.ins);
			else if (mMR.resolved() && r.ref >= mMR.address() && r.ref < mMR.address() + sizeof(MappedRegions))
				std::println("{:X} > MR + 0x{:X} [{}]", r.ins->rva, r.ref - mMR.address(), *r.ins);
			else
				std::println("{:X} > {} [{}]", r.ins->rva, mBinary.formatRVA(r.ref), *r.ins);
		}
	}


private:
	bool mApplyRuntimePatches;
	PEBinary mBinary;
	Patcher mPatcher;
	OldFunctionTable mFuncs;
	FunctionTable mFuncTable;

	ResolvedGlobalAddress<BootstrapStartState, Section::Data> mBSS;
	ResolvedGlobalAddress<AntitamperStaticState, Section::Data> mASS;
	ResolvedGlobalAddress<MappedRegions, Section::RData> mMR;
	ResolvedAddress<Section::Text> mShuffle;
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
	ResolvedAddress<Section::Text> mTLSDecode;
	ResolvedAddress<Section::Text> mTLSFixup;
	ResolvedAddress<Section::Text> mTLSRuntime;
	ResolvedAddress<Section::Text> mVEHMain;
	ResolvedAddress<Section::Text> mVEHHashRegionStart;
	ResolvedAddress<Section::Text> mVEHHashRegionEnd;
	ResolvedAddress<Section::Text> mVEHContinuationFail;
	ResolvedAddress<Section::Text> mObfuscate;
	ResolvedAddress<Section::Text> mImportFail;
	ResolvedAddress<Section::Text> mUnencryptedStart;
	ResolvedAddress<Section::Text> mUnencryptedEnd;
	ResolvedAddress<Section::Text> mRemappedSegmentState;
	ResolvedAddress<Section::Text> mRemappedSegmentCount;
};

int main(int argc, char* argv[])
{
	//analysis::unittestJumpChains();
	if (argc < 2)
	{
		std::println("File name expected");
		return 1;
	}

	try
	{
		SC2Binary bin(argv[1], true);
		return 0;
	}
	catch (std::exception& e)
	{
		std::println("Error: {}", e.what());
		return 2;
	}
}
