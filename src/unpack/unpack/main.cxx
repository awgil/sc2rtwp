#include <common/win_headers.h>

import unpack.known_structs;
import unpack.patcher;
import unpack.function_table;
import unpack.ida_export;

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
	void exportToIDA(IDAExporter& exporter, std::string_view name) { exporter.registerGlobal<T>(this->address(), name); }
};

template<typename T> T getSimpleXorConstant(PEBinary& bin, const analysis::Reference& ref)
{
	auto it = ref.ins;
	// supported sequences:
	//                            xor r1, const; mov mem, r1
	// mov r2, const;             xor r1, r2;    mov mem, r1
	// mov r2, const; mov r1, r3; xor r1, r2;    mov mem, r1

	T constant = 0;
	ensure(it->mnem == X86_INS_MOV && it->ops[0].type == x86::OpType::Mem && it->ops[1].type == x86::OpType::Reg);
	auto finalReg = it->ops[1].reg;

	--it;
	ensure(it->mnem == X86_INS_XOR && it->ops[0] == finalReg);
	if (it->ops[1].type == x86::OpType::Imm)
	{
		// simple form, xor with immediate
		constant = it->ops[1].immediate<T>();
	}
	else if (it->ops[1].type == x86::OpType::Reg)
	{
		auto interReg = it->ops[1].reg;

		--it;
		while (it->mnem == X86_INS_MOV)
		{
			ensure(it->ops[0].type == x86::OpType::Reg && it->ops[1].type == x86::OpType::Reg);
			if (finalReg == it->ops[0].reg)
				finalReg = it->ops[1].reg;
			else if (interReg == it->ops[0].reg)
				interReg = it->ops[1].reg;
			else
				throw std::exception("Unexpected mov");

			--it;
		}

		ensure(it->mnem == X86_INS_MOVABS && it->ops[1].type == x86::OpType::Imm);
		ensure(it->ops[0] == interReg || it->ops[0] == finalReg);
		constant = it->ops[1].immediate<T>();
	}
	else
	{
		throw std::exception("Unsupported xor operand");
	}

	// it so happens that initial value for a xorred value is equal to the xor constant (i.e. the initial effective value is zero)
	// nothing actually relies on that afaik, but it's a good sanity check
	auto initialValue = *bin.structAtRVA<T>(ref.ref);
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

	void resolve(const analysis::Reference& ref, PEBinary& bin)
	{
		auto value = getSimpleXorConstant<T>(bin, ref);
		if (mConstant == 0)
		{
			std::println("XOR constant 0x{:016X} for {} at {} written by instruction at {}", value, mDebugName, bin.formatRVA(ref.ref), bin.formatRVA(ref.ins->rva));
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

// find next/prev instruction by mnemonic
const x86::Instruction* findNextInstruction(const x86::Instruction* ins, x86::Mnem mnem, bool forward, int order = 1)
{
	auto delta = forward ? 1 : -1;
	while (order--)
		while ((ins += delta)->mnem != mnem)
			;
	return ins;
}

// TODO: RTTI?
class SC2Binary
{
public:
	SC2Binary(const std::filesystem::path& path, bool applyIDAPatches, bool applyRuntimePatches)
		: mApplyRuntimePatches(applyRuntimePatches)
		, mBinary(path)
		, mPatcher(mBinary, applyIDAPatches, applyRuntimePatches)
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
		processTLSInitial();
		processTLSDecode();
		processBootstrapJunk();
		processTLSFixup();

		// process SEH stuff now that it's decoded - it's important to find _C_specific_handler, so that we know to parse C_SCOPE_TABLE SEH structures and add exception handler blocks...
		mFuncTable.analyzeSEHHandlers();

		processTLSRuntime();

		// process all remaining functions recursively
		mFuncTable.analyzeAllRemaining();

		// sanity checks
		//for (auto& func : mFuncTable.entries())
		//	if (func.value.analyzed)
		//		for (auto& hlt : func.value.analyzed->instructions | std::views::filter([](const auto& ins) { return ins.mnem == X86_INS_HLT; }))
		//			ensure(mBinary.bytes()[hlt.rva] != 0xF4);

		{
			auto idaPath = path;
			idaPath.replace_extension(".py");
			IDAExporter exporter{ idaPath };
			mBSS.exportToIDA(exporter, "gBSS");
			mASS.exportToIDA(exporter, "gASS");
			mMR.exportToIDA(exporter, "gMR");
			exporter.registerGlobalName(mShuffle.address(), "gShuffle");
			for (auto& [_, e] : mFuncTable.entries())
				if (e.isAnalyzed())
					exporter.registerFunction(e.begin, e.end, e.name);
		}

		auto fixedPath = path;
		fixedPath.replace_extension(std::format(".fixed{}{}.exe", applyIDAPatches ? "_ida" : "", applyRuntimePatches ? "_rt" : ""));
		mBinary.save(fixedPath);
	}

private:
	// process fallback start function
	void processBootstrapStart()
	{
		// note: bootstrap function is noreturn, and the very last block containing 'normal' return is unreachable
		auto& func = mFuncTable.analyze(mBinary.entryPoint(), "bootstrapStart");

		// we don't care about rdata refs here, these are error messages
		resolveRefs(func.refs | std::views::filter([&](const auto& r) { return !sectionRData().contains(r.ref); }),
			&BootstrapStartState::stage);
		ensure(mBSS.address() - sectionData().begin == 0x60); // not sure what's there before it and how likely is it to change...
	}

	// initial tls callback
	void processTLSInitial()
	{
		// note: tls directory is in .rdata, just preceding RTTI data...
		ensure(mBinary.tlsCallbackRVAs().size() == 1);
		auto& func = mFuncTable.analyze(mBinary.tlsCallbackRVAs().front(), "bootstrapTLSInitial");
		resolveRefs(func.refs,
			&BootstrapStartState::stage,
			&AntitamperStaticState::xorConstants,
			&AntitamperStaticState::supportSSE, // processor caps flags
			&AntitamperStaticState::pageHashUsesAVX2, // last flag
			mTLSRuntime,
			mTLSDecode,
			mTLSFixup);
		// note: RTTI between tls directory and antidebug static ?..

		// the xor constant init looks like this:
		// (r0 == 0, r1 == length)
		//   cmp r0, r1
		//   jnb loop_end
		//   mov r2, r0
		//   lea r3, [xorconstants]
		//   add r2, r3
		// loop_body:
		//   ... inc r0 ...
		//   cmp r0, r1
		//   jb loop_body
		// loop_end: ...
		// so we find preceeding jnb, and then sanity check that target is preceeded by a loop back jump
		ensure(func.refs[1].ins->mnem == X86_INS_LEA);
		auto xorInit = findNextInstruction(func.refs[1].ins, X86_INS_JAE, false);
		ensure(xorInit[-1].mnem == X86_INS_CMP);
		ensure(xorInit->ops[0].immediate<rva_t>() > func.refs[1].ins->rva);
		mPatcher.patchJumpToUnconditional(xorInit->rva, "xor constants init");
	}

	// main decoding tls callback
	void processTLSDecode()
	{
		auto& func = processWrapperFunc(mTLSDecode.address(), "bootstrapTLSDecode", &BootstrapStartState::stage);
		mPatcher.patchHlts(func);

		auto iRef = func.refs.begin();
		resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHash);
		resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		auto imagebaseReg = matchImagebaseLoad(*iRef++); // this is kinda bad, this is used to fill relocationsStraddlingPageBoundary
		resolveRef(*iRef++, &AntitamperStaticState::relocationsStraddlingPageBoundaryCount);
		processVEH(iRef++->ref);
		if (iRef->ref == 0)
			imagebaseReg = matchImagebaseLoad(*iRef++); // sucks, used to do forbidden module decoding

		processEmptyFunc(iRef++->ref, "bootstrapAnyModuleLoaded");

		ResolvedAddress<Section::Text> remapSections, remapSectionsEnd;
		resolveRef(*iRef++, remapSectionsEnd);
		resolveRef(*iRef++, remapSections);
		ensure(remapSectionsEnd.address() > remapSections.address());
		processEmptyFunc(remapSections.address(), "bootstrapRemapSections");

		// the next is alloc of ADS, followed by retval check, followed by random-fill loop
		auto adsFill = resolveRefGetIns(*iRef++, mXorVirtualAlloc.field());
		adsFill = findNextInstruction(adsFill, X86_INS_JE, true, 2); // first jump bails if VirtualAlloc failed, second jump is what we care about
		ensure((adsFill - 1)->mnem == X86_INS_TEST);
		mPatcher.patchJumpToUnconditional(adsFill->rva, "random fill antitamper debug state");

		resolveRef(*iRef++, mXorNtCreateSection.field());
		resolveRef(*iRef++, mXorMapViewOfFileEx.field());
		resolveRef(*iRef++, mXorVirtualProtect.field());
		resolveRef(*iRef++, mXorUnmapViewOfFile.field());
		resolveRef(*iRef++, mXorMapViewOfFileEx.field());
		resolveRef(*iRef++, mXorVirtualProtect.field());
		resolveRef(*iRef++, &BootstrapInfo::sections);
		resolveRef(*iRef++, &BootstrapStartState::stage);
		resolveRef(*iRef++, &BootstrapInfo::textRVA);
		resolveRef(*iRef++, &BootstrapInfo::textSize);
		resolveRef(*iRef++, &MappedRegions::textSection);
		resolveRef(*iRef++, &MappedRegions::executableRegion);
		resolveRef(*iRef++, &BootstrapInfo::rdataRVA);
		resolveRef(*iRef++, &BootstrapInfo::rdataSize);
		resolveRef(*iRef++, &MappedRegions::rdataSection);

		resolveRef(*iRef++, &BootstrapInfo::textRVA); // note: this is loaded just to clobber the field, patch?..
		resolveRef(*iRef++, &BootstrapInfo::rdataRVA); // note: this is loaded just to clobber the field, patch?..

		resolveRef(*iRef++, &AntitamperStaticState::writableSectionMapping);
		resolveRef(*iRef++, &AntitamperStaticState::vehDecryptionDone);
		resolveRef(*iRef++, &AntitamperStaticState::vehDecryptionFailed);
		ensure(sectionText().contains(iRef++->ref)); // ??? some sort of failure handler, looks encrypted, or just junk?..
		resolveRef(*iRef++, &AntitamperStaticState::vehDecryptionDone);
		resolveRef(*iRef++, mObfuscate);
		imagebaseReg = matchImagebaseLoad(*iRef++); // used for reading xor constants

		// the next is alloc of page hash, and then pointer and page count are saved in ADS
		// page count is calculated by dividing image size by 4096 (div reg instruction) - on runtime, we want to patch it out with 1
		auto pageHash = resolveRefGetIns(*iRef++, mXorVirtualAlloc.field());
		// find div reg32; we want to patch it to 'mov eax, 1', but we need more space...
		// this is preceeded by mov reg64, ... - we patch both instructions
		pageHash = findNextInstruction(pageHash, X86_INS_DIV, true);
		ensure(pageHash->ops[0].type == x86::OpType::Reg && pageHash->ops[0].reg.isGPR32());
		auto pageHashPre = pageHash - 1;
		ensure(pageHashPre->mnem == X86_INS_MOV && pageHashPre->ops[0] == x86::Reg::makeGPR64(pageHash->ops[0].reg.gprIndex()));
		const u8 movEax1[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 };
		mPatcher.patchGeneric(movEax1, pageHashPre->rva, pageHash->endRVA(), "page hash size");

		// different versions of executable reload imagebase, obfuscate function or xor constant from now on at random places; skip that
		// also skip random .rdata references (used by avx hashing)
		auto skipUninteresting = [&]() {
			while (iRef->ref == 0 || iRef->ref == mObfuscate.address() ||
				iRef->ref >= mASS.address() + fieldOffset(&AntitamperStaticState::xorConstants) && iRef->ref < mASS.address() + fieldOffset(&AntitamperStaticState::delayedCrashEncodedState) ||
				sectionRData().contains(iRef->ref))
			{
				++iRef;
			}
		};
		skipUninteresting();

		processInitADS(iRef++->ref);
		resolveRef(*iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		resolveRef(*iRef++, &AntitamperStaticState::bootstrapVEHHandle); // remove veh handler
		resolveRef(*iRef++, &BootstrapStartState::stage); // enter stage F
		processEmptyFunc(iRef++->ref, "bootstrapGetKernel32APIs");
		skipUninteresting();
		processDecryptImports(iRef++->ref);

		// decode bootstrap info, now that we've found shuffle - TODO: move outside?..
		mPatcher.decryptModifiedRC4({ mShuffle.access(mBinary), 16 }, mBSS.access(mBinary)->encryptedInfo);

		resolveRef(*iRef++, &BootstrapInfo::pageRegions);
		resolveRef(*iRef++, mUnencryptedStart);
		resolveRef(*iRef++, mUnencryptedEnd);
		ensure(mUnencryptedStart.address() == sectionText().begin && sectionText().contains(mUnencryptedEnd.address()));
		resolveRef(*iRef++, &BootstrapStartState::stage); // enter stage D

		skipUninteresting();
		processDecryptPage(iRef++->ref, "Var3");
		skipUninteresting();
		auto decryptPage12 = iRef++->ref;
		processDecryptPage(decryptPage12, "Var12");
		skipUninteresting();
		ensure(iRef++->ref == decryptPage12);
		skipUninteresting();
		processDecryptPage(iRef++->ref, "Var0");
		resolveRef(*iRef++, mUnencryptedEnd);
		resolveRef(*iRef++, mUnencryptedStart);
		decodePages();
		// note: there's a loop here that clobbers page region data, we could patch it out if we cared...
		processLeafFunc(iRef++->ref, "bootstrapProcessNewThread");

		// copy expected remapped section state
		// TODO: rewrite this to skip the checks, so that we can do veh debugger stuff...
		resolveRef(*iRef++, mRemappedSegmentState);
		resolveRef(*iRef++, mRemappedSegmentCount);
		// TODO: nop out next loop, which random-fills the state array
		resolveRef(*iRef++, &BootstrapInfo::sections);
		skipUninteresting();

		// and then hash it (state and count)
		resolveRef(*iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		resolveRef(*iRef++, &AntitamperStaticState::supportSSE);
		resolveRef(*iRef++, &AntitamperStaticState::pageHashUsesAVX2);
		skipUninteresting();
		resolveRef(*iRef++, &AntitamperStaticState::dynState);
		skipUninteresting();
		resolveRef(*iRef++, &AntitamperStaticState::supportSSE);
		resolveRef(*iRef++, &AntitamperStaticState::pageHashUsesAVX2);
		skipUninteresting();

		// code that sets up two mappings to the same random region in bootstrap code
		ensure(iRef++->ref == func.begin);
		skipUninteresting();

		resolveRef(*iRef++, mXorCloseHandle.field()); // close mapping
		// TODO: nop out PE header fuckup?
		resolveRef(*iRef++, mXorVirtualProtect.field()); // restore protection
		resolveRef(*iRef++, &AntitamperStaticState::tlsDecryptionDone);
		ensure(iRef == func.refs.end());

		// find the loop that decodes bootstrap info, so that we can skip it on runtime
		// the reference is typically reg+rva, with reg being set to imagebase before - so we look by displacement...
		auto decodeInfo = std::ranges::find_if(func.instructions, [addr = mBSS.address() + fieldOffset(&BootstrapStartState::encryptedInfo)](const auto& ins) {
			return ins.mnem == X86_INS_XOR && ins.ops[0].type == x86::OpType::Mem && ins.ops[0].mem.displacement == addr;
		});
		ensure(decodeInfo != func.instructions.end());
		while ((--decodeInfo)->mnem != X86_INS_JAE)
			;
		ensure(decodeInfo[-1].mnem == X86_INS_CMP && decodeInfo[-1].ops[1] == sizeof BootstrapInfo);
		mPatcher.patchJumpToUnconditional(decodeInfo->rva, "decrypt bootstrap info");
	}

	// process everything related to VEH - it deals with creating one of the obfuscate() variants
	void processVEH(rva_t rvaSetupVEH)
	{
		auto& funcSetup = mFuncTable.analyze(rvaSetupVEH, "bootstrapSetupVEH");
		mPatcher.patchHlts(funcSetup);
		resolveRefs(funcSetup.refs,
			mXorRtlAddVectoredExceptionHandler,
			mVEHMain,
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

		auto& funcMain = processWrapperFunc(mVEHMain.address(), "bootstrapVEHMain");
		resolveRefs(funcMain.refs | std::views::filter([](const auto& ref) { return ref.ins->mnem != X86_INS_CALL; }),
			&AntitamperStaticState::bootstrapVEHInvocationCount, // comparison, reset & increment
			&AntitamperStaticState::bootstrapVEHInvocationCount,
			&AntitamperStaticState::bootstrapVEHInvocationCount,
			mXorVEHRetval,
			mXorVEHRetval.field(),
			mXorVEHLastExcInfo,
			&BootstrapStartState::vehVal4,
			&BootstrapStartState::vehVal1,
			&AntitamperStaticState::writableSectionMapping,
			mVEHHashRegionEnd,
			mVEHHashRegionStart,
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
			mVEHContinuationFail,
			&BootstrapStartState::vehVal9,
			&BootstrapStartState::vehVal9,
			&BootstrapStartState::vehVal9);
		ensure(mVEHHashRegionEnd.address() > mVEHHashRegionStart.address());
		processEmptyFunc(mVEHContinuationFail.address(), "bootstrapVEHContinuationFail");

		for (int i = 1; auto& call : funcMain.refs | std::views::filter([](const auto& ref) { return ref.ins->mnem == X86_INS_CALL; }))
			processVEHSub(call.ref, i++);
	}

	// note: index is 1-based for legacy reasons (that's how i called subfunctions while reversing)
	void processVEHSub(rva_t rva, int index)
	{
		ensure(index > 0 && index <= 15);
		auto& func = mFuncTable.analyze(rva, std::format("bootstrapVEHSub{}", index));
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
		ensure(func.refs.size() >= 9);
		auto iRef = func.refs.begin();

		// match prologue
		resolveRef(*iRef++, mXorVEHLastExcInfo.field());
		auto numCallsRVA = mASS.address() + fieldOffset(&AntitamperStaticState::bootstrapVEHSubInvocationCount) + sizeof(u32) * (index - 1);
		ensure(iRef++->ref == numCallsRVA);

		// bootstrap region rehash logic is repeated in a few functions
		if (index == 1 || index == 2 || index == 5 || index == 8 || index == 10)
		{
			resolveRef(*iRef++, mVEHHashRegionEnd);
			resolveRef(*iRef++, mVEHHashRegionStart);
			resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHash);
			resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHash);
			resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
			resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		}

		// some weird hashing logic, the hash result is not actually used anywhere...
		if (index == 3 || index == 7 || index == 12 || index == 13 || index == 15)
		{
			ensure(sectionText().contains(iRef++->ref));
			ensure(sectionText().contains(iRef++->ref));
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
		auto valOffset = perIndexFieldOffsets[index - 1];
		if (valOffset)
			ensure(iRef++->ref == mBSS.address() + valOffset);

		// the main function that decrypts obfuscate()
		if (index == 14)
		{
			// TODO: do full constant propagation logic, both for base RVA and polynomial constants
			ensure(sectionText().contains(iRef++->ref)); // after adjustment: base RVA containing encrypted versions of obfuscate
			//auto decodeLoopAddr = iRef->ins->rva;
			resolveRef(*iRef++, mObfuscate); // RVA of obfuscate - note that it might be offset by a constant!
			ensure(iRef++->ref == 0); // imagebase used for VA->RVA conversion...
			auto obfuscateRead = resolveRefGetIns(*iRef++, &AntitamperStaticState::writableSectionMapping); // read the original byte to be decrypted
			resolveRef(*iRef++, &MappedRegions::textSection);
			ensure(iRef++->ref == mMR.address() + fieldOffset(&MappedRegions::textSection) + fieldOffset(&MappedRegionInfo::size));
			resolveRef(*iRef++, &AntitamperStaticState::writableSectionMapping); // used to write back decrypted implementation
			resolveRef(*iRef++, &AntitamperStaticState::vehDecryptionDone); // TODO: store constant?..
			if (sectionText().contains(iRef->ref))
			{
				// sometimes compiler might reload address of obfuscate function here, and now it seems to be done directly without adjustment...
				mObfuscate = {};
				resolveRef(*iRef++, mObfuscate);
			}
			resolveRef(*iRef++, &AntitamperStaticState::xorConstants);
			resolveRef(*iRef++, &AntitamperStaticState::obfuscateFunctionHash);
			resolveRef(*iRef++, &AntitamperStaticState::obfuscateUnk);

			// write the fake implementation of obfuscate
			// we have two options here - a no-op, or one that would replace constants with zeros
			const u8 obfuscateImpl[] = {
				0x31, 0xC0, // xor eax, eax
				0x48, 0x89, 0x01, // mov [rcx], rax
				0x48, 0x89, 0x02, // mov [rdx], rax
				0xC3 // ret
			};
			mPatcher.patchGeneric(obfuscateImpl, mObfuscate.address(), mObfuscate.address() + 0x400, "no-op obfuscate", false);
			processEmptyFunc(mObfuscate.address(), "obfuscate");

			// and now we need a runtime patch
			// simplest possible is to replace the instruction in the loop that builds decrypted buffer - instead of xorring the encrypted variant with key byte, just overwrite it
			// in more details - there's a local buffer that is used to decode one of the 16 versions, the code does the following:
			// - first, it reads one of the encrypted versions into our buffer
			// - then, it runs the RC4-like algorithm to build another permutation buffer and use that to transform the main buffer
			// - finally, it xors the buffer with what obfuscate location contains - this is what we patch!
			// - after that, it does post processing steps that we leave as is (ie patching some magic constants in decrypted version and calculating FNV1 hash)
			obfuscateRead = findNextInstruction(obfuscateRead, X86_INS_XOR, true);
			mPatcher.patchXorToMov(obfuscateRead->rva, "decrypt obfuscate()");
		}

		// match epilogue
		ensure(iRef++->ref == numCallsRVA);
		resolveRef(*iRef++, &AntitamperStaticState::bootstrapRegionHashMismatch);
		resolveRef(*iRef++, mXorVEHLastExcInfo.field());
		resolveRef(*iRef++, mVEHContinuationFail);
		resolveRef(*iRef++, mXorVEHLastExcInfo.field());
		resolveRef(*iRef++, mXorVEHRetval.field());
		ensure(iRef++->ref == numCallsRVA);

		ensure(iRef == func.refs.end());
	}

	void processInitADS(rva_t rva)
	{
		auto& func = mFuncTable.analyze(rva, "bootstrapInitAntitamperDynamicState");
		mPatcher.patchHlts(func);
		// data refs are not interesting, to xor constants and then to a bunch of functions
		// note: there's some reference to beyond import table (in .rdata), what's this?..
		resolveRefs(func.refs | std::views::filter([&](const auto& ref) { return sectionText().contains(ref.ref); }), mObfuscate, mTLSRuntime);
	}

	void processDecryptImports(rva_t rva)
	{
		auto& func = mFuncTable.analyze(rva, "bootstrapDecryptImports");
		resolveRefs(func.refs,
			mShuffle,
			&AntitamperStaticState::failedImportLibName,
			mShuffle,
			&AntitamperStaticState::failedImportFuncName,
			&AntitamperStaticState::failedImportLibName,
			mImportFail);

		decodeImports();

		// just replace the entire function with 'return true'
		const u8 replacement[] = {
			0xB0, 0x01, // mov al, 1
			0xC3, // ret
		};
		mPatcher.patchGeneric(replacement, func.begin, func.end, "decrypt import skip");
	}

	void processDecryptPage(rva_t rva, std::string_view tag)
	{
		// nothing interesting in any of these...
		auto& func = processLeafFunc(rva, std::format("bootstrapDecryptPage{}", tag));

		// since we're decrypting all pages manually, we need to patch a loop that does it on runtime
		auto fnvWrite = std::ranges::find_if(func.refs, [addr = mASS.address() + fieldOffset(&AntitamperStaticState::prevDecryptedPageHash)](const auto& ref) { return ref.ref == addr; });
		ensure(fnvWrite != func.refs.end());
		ensure(fnvWrite->iop == 0 && fnvWrite->ins->mnem == X86_INS_MOV);
		// note: consider more robust check:
		// - we have an instruction that updates the FNV1, find the beginning of the loop that calculates it (mov reg, 0xCBF29CE484222325)
		// - find end of the previous loop by skipping preceding jmps (from jump chain), if any
		// - ensure preceding non-nop instruction is jnz to the loop body start
		// - jnb right before loop body start is the one we're looking for
		auto decodeLoopSkip = findNextInstruction(fnvWrite->ins, X86_INS_JAE, false);
		mPatcher.patchJumpToUnconditional(decodeLoopSkip->rva, "decrypt page");
	}

	void processTLSFixup()
	{
		auto& func = processWrapperFunc(mTLSFixup.address(), "bootstrapTLSFixup", &BootstrapStartState::stage);
		ResolvedAddress<Section::Text> tlsDummy;
		resolveRefs(func.refs,
			&AntitamperStaticState::dynState,
			mObfuscate,
			&AntitamperStaticState::xorConstants,
			&AntitamperStaticState::tlsDecryptionDone,
			tlsDummy, // replace 2nd & 3rd tls callbacks with dummy func
			&BootstrapInfo::rvaEntryPoint, // read real entrypoint
			&BootstrapInfo::rvaEntryPoint, // patch with random stuff (TODO: nop out the loop)
			mVEHHashRegionStart, // the next code overwrites the entire bootstrap section with random stuff; TODO reconsider...
			mVEHHashRegionEnd,
			mBinary.entryPoint()); // patching out the entrypoint to jump to real one

		processEmptyFunc(tlsDummy.address(), "bootstrapTLSDummy");

		if (mPatcher.applyIDAOnlyPatches()) // TODO: do *not* do this for runtime, at least unless patching the tls fixup...
		{
			// patch the entrypoint to the real one
			auto realEntryPoint = mBSS.access(mBinary)->encryptedInfo.rvaEntryPoint;
			mBinary.peHeader().OptionalHeader.AddressOfEntryPoint = realEntryPoint;
		}
	}

	void processTLSRuntime()
	{
		auto& func = processEmptyFunc(mTLSRuntime.address(), "tlsRuntime"); // everything there is done by filter

		auto& sehHandlers = mFuncTable.entries().find(mTLSRuntime.address())->second.exceptionHandlers;
		ensure(sehHandlers.size() == 1);

		ResolvedAddress<Section::Text> filter;
		resolveRefs(mFuncTable.analyze(sehHandlers[0], "tlsRuntimeSEHFilter").refs, filter);

		auto& impl = processWrapperFunc(filter.address(), "tlsRuntimeFilter");
		// TODO: deal with it all...
		ensure(std::ranges::all_of(impl.refs, [&](const auto& ref) { return ref.ref == mObfuscate.address() || !sectionText().contains(ref.ref); }));
	}

	void processBootstrapJunk()
	{
		// there are a bunch of SEH entries pointing to bootstrap area with bad data; replace all that with simple dummy functions to help out IDA
		auto it = mFuncTable.entries().find(mVEHMain.address());
		ensure(it != mFuncTable.entries().end() && it->second.isAnalyzed());
		++it;
		ensure(it != mFuncTable.entries().end() && it->second.isAnalyzed()); // impl
		++it;
		auto limit = mBinary.entryPoint();
		int index = 0;
		const u8 patch[] = { 0xC3 }; // ret
		while (it != mFuncTable.entries().end() && it->first < limit)
		{
			ensure(!it->second.isAnalyzed() && it->second.seh);
			mPatcher.patchGeneric(patch, it->second.begin, it->second.end, "fake bootstrap entry", false);
			mFuncTable.analyze(it->second.begin, std::format("bootstrapDummy{}", index++));
			++it;
		}
	}

	FunctionInfo& processEmptyFunc(rva_t rva, std::string_view name)
	{
		auto& func = mFuncTable.analyze(rva, name);
		ensure(func.refs.empty());
		return func;
	}

	auto& processLeafFunc(rva_t rva, std::string_view name)
	{
		auto& func = mFuncTable.analyze(rva, name);
		ensure(std::ranges::all_of(func.refs, [&](const auto& ref) { return ref.ref == mObfuscate.address() || !sectionText().contains(ref.ref); }));
		return func;
	}

	template<typename... Fields>
	auto& processWrapperFunc(rva_t wrapperRVA, const std::string& name, Fields&&... dataRefs)
	{
		ResolvedAddress<Section::Text> implAddr;
		resolveRefs(mFuncTable.analyze(wrapperRVA, name).refs, std::forward<Fields>(dataRefs)..., implAddr);
		return mFuncTable.analyze(implAddr.address(), name + "Impl");
	}

	void decodeImports()
	{
		int shuffleIndex = 0;
		auto shuffle = mShuffle.access(mBinary);
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
			auto shuffle = mShuffle.access(mBinary) + 506 * (pageIndex % 166);

			u8 key[506];
			for (int i = 0; i < sizeof key; ++i)
				key[i] = shuffle[i] ^ prevPageFNV1Ptr[i & 7];

			auto data = std::span(mBinary.structAtRVA<unsigned char>(pageStart), 4096);
			mPatcher.decryptModifiedRC4(key, data);
			prevPageFNV1 = fnv1a64(data);
		}
	}

	i64 fnv1a64(std::span<const u8> data)
	{
		i64 result = 0xCBF29CE484222325ll; // FNV offset basis
		for (auto& b : data)
		{
			result ^= b;
			result *= 0x100000001B3ll; // FNV prime
		}
		return result;
	}

	// new stuff ...
	const PEBinary::Section& section(Section id) { return mBinary.sections()[static_cast<int>(id)]; }
	const PEBinary::Section& sectionText() { return section(Section::Text); }
	const PEBinary::Section& sectionRData() { return section(Section::RData); }
	const PEBinary::Section& sectionData() { return section(Section::Data); }

	void resolveRefs(auto&& refs, auto&&... resolvers)
	{
		auto it = std::ranges::begin(refs);
		auto end = std::ranges::end(refs);
		((ensure(it != end), resolveRef(*it++, std::forward<decltype(resolvers)>(resolvers))), ...);
		ensure(it == end);
	}

	void resolveRef(const analysis::Reference& ref, rva_t rva) { ensure(ref.ref == rva); }
	template<typename R> void resolveRef(const analysis::Reference& ref, R (BootstrapStartState::*field)) { mBSS.resolve(ref.ref - fieldOffset(&BootstrapStartState::encryptedInfo) - fieldOffset(field), mBinary); }
	template<typename R> void resolveRef(const analysis::Reference& ref, R (BootstrapInfo::*field)) { mBSS.resolve(ref.ref - fieldOffset(field), mBinary); }
	template<typename R> void resolveRef(const analysis::Reference& ref, R (AntitamperStaticState::*field)) { mASS.resolve(ref.ref - fieldOffset(field), mBinary); }
	template<typename R> void resolveRef(const analysis::Reference& ref, R (MappedRegions::*field)) { mMR.resolve(ref.ref - fieldOffset(field), mBinary); }
	template<Section S> void resolveRef(const analysis::Reference& ref, ResolvedAddress<S>& addr) { addr.resolve(ref.ref, mBinary); }
	template<typename T, typename C> void resolveRef(const analysis::Reference& ref, XorredField<T, C>& field) { field.resolve(ref, mBinary); }

	const x86::Instruction* resolveRefGetIns(const analysis::Reference& ref, auto&& resolver) { resolveRef(ref, std::forward<decltype(resolver)>(resolver)); return ref.ins; }

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

	// match lea reg, imagebase ref
	// this is jank, ideally we need proper constant propagation analysis...
	x86::Reg matchImagebaseLoad(const analysis::Reference& ref)
	{
		ensure(ref.ref == 0);
		ensure(ref.ins->mnem == X86_INS_LEA && ref.ins->ops[0].type == x86::OpType::Reg);
		return ref.ins->ops[0].reg;
	}

private:
	bool mApplyRuntimePatches;
	PEBinary mBinary;
	Patcher mPatcher;
	FunctionTable mFuncTable;

	ResolvedGlobalAddress<BootstrapStartState, Section::Data> mBSS;
	ResolvedGlobalAddress<AntitamperStaticState, Section::Data> mASS;
	ResolvedGlobalAddress<MappedRegions, Section::RData> mMR;
	ResolvedGlobalAddress<u8, Section::RData> mShuffle;
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
		SC2Binary bin(argv[1], true, false);
		return 0;
	}
	catch (std::exception& e)
	{
		std::println("Error: {}", e.what());
		return 2;
	}
}
