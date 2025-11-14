#ifndef CHECK_SIZE
#define CHECK_SIZE(struct, size)
#define u8 unsigned char
#define u32 unsigned int
#define u64 unsigned long long
#endif

struct SectionRemapInfo
{
	u32 fileOffset;
	u32 size;
	u32 desiredAccess;
};
CHECK_SIZE(SectionRemapInfo, 0xC);

struct AddressSizePair
{
	u32 rva;
	u32 size;
};
CHECK_SIZE(AddressSizePair, 0x8);

struct BootstrapInfo
{
	u32 f0;
	u32 rvaEntryPoint;
	SectionRemapInfo sections[32];
	AddressSizePair pageRegions[32];
	AddressSizePair f288[32];
	u32 textRVA;
	u32 textSize;
	u32 rdataRVA;
	u32 rdataSize;
};
CHECK_SIZE(BootstrapInfo, 0x398);

struct BootstrapStartState
{
	BootstrapInfo encryptedInfo;
	u64 defaultImageBase;
	wchar_t stage;
	u64 encryptedForbiddenModule[2];
	u64 xorredRtlAddVectoredExceptionHandler;
	u64 xorredCloseHandle;
	u64 xorredVirtualAlloc;
	u64 xorredNtCreateSection;
	u64 xorredMapViewOfFileEx;
	u64 xorredVirtualProtect;
	u64 xorredUnmapViewOfFile;
	u64 xorredRemoveVectoredExceptionHandler;
	u8 vehVal4;
	u8 vehVal6;
	u32 vehVal11;
	u32 vehVal9;
	u32 vehXorredRetval;
	u64 vehXorredLastExceptionInfo;
	u32 vehVal1;
	u32 vehVal2;
};
CHECK_SIZE(BootstrapStartState, 0x418);

struct MappedRegionInfo
{
	void* ptr;
	int size;
};
CHECK_SIZE(MappedRegionInfo, 0x10);

// known executable regions, stored in .rdata
struct MappedRegions
{
	MappedRegionInfo textSection; // bounds match .text but are read from bootstrap info
	MappedRegionInfo executableRegion; // bounds are union of all sections marked as executable in PE header
	MappedRegionInfo rdataSection; // bounds match .rdata but are read from bootstrap info
};
CHECK_SIZE(MappedRegions, 0x30);

// heap-allocated part of the antitamper state
// most fields are encoded, the algorithm is hardcoded everywhere it's accessed and uses some hardcoded constants - won't be surprised if they are different in every build
struct AntitamperDynamicState
{
};

// the main structure describing everything related to anti-tamper measures
// the instance is stored in .data section right after RTTI objects, easy to find
struct AntitamperStaticState
{
	u32 currentCrashReason; // usually 0, set to reason field when crash process starts; used to pass information to SEH filter or something
	AntitamperDynamicState* dynState;
	void* pageHashMismatchCallback; // an optional callback executed when page hash mismatch is detected; it's null on runtime (some leftover debug thing?) and callers validate it's inside main code section
	bool supportSSE;
	bool supportSSE2;
	bool supportSSE41;
	bool supportSSE42;
	bool supportAVX;
	bool supportAVX2;
	bool pageHashUsesSSE42; // == supportSSE42, related to page hashing
	bool pageHashUsesSSE2; // == supportSSE2, related to page hashing
	bool pageHashUsesAVX2; // == supportAVX && supportAVX2 && windows version is 6.3 or >= 10

	// this is filled out by TLS callback, don't know whether it's used by something (some antidebug checks that detect injected threads maybe?)
	u32 knownThreadsSpinlock;
	u64 pad0;
	u64 knownThreads[256];

	u8 xorConstants[4096 + 8]; // these are used for decoding various things - u64's are read from here with random offsets in [0, 0xFFF] range

	u64 delayedCrashEncodedState[6];
	u64 delayedCrashEncryptionKey;
	u32 delayedCrashSpinlock;
	u32 pad1;

	char f1878[0x218]; // no idea what's here...

	u64 obfuscateFunctionHash; // hash of the page containing obfuscate() function, obfuscated using it...
	u64 obfuscateUnk; // ??? obfuscated zero ?..

	char f1aa0[0x420]; // no idea what's here...

	bool vehDecryptionFailed; // ???
	u64 bootstrapRegionHash;
	u64 bootstrapRegionHashMismatch;
	void* writableSectionMapping; // plain pointer to writable mapping of the entire executable
	u64 vehDecryptionDone; // initially 0, set to some constant when obfuscate() is decrypted
	u64 pad2;

	AddressSizePair relocationsStraddlingPageBoundary[128];
	u32 relocationsStraddlingPageBoundaryCount;
	u32 pad3[3];

	char failedImportLibName[260];
	char failedImportFuncName[1024];
	u32 pad4;

	u64 tlsDecryptionDone;
	u64 bootstrapVEHHandle;
	u64 prevDecryptedPageHash;
	u64 pfnNtQueryInformationThread;
	u32 bootstrapVEHInvocationCount;
	u32 bootstrapVEHSubInvocationCount[15];
};
CHECK_SIZE(AntitamperStaticState, 0x2868);
