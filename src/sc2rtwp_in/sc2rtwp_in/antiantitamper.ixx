export module injected.antiantitamper;

import injected.logger;
import injected.app;
import injected.cs.antitamper;

// SC2 has several tamper detection methods that we need to work around:
// 1. For some of the pages (containing code or constant data) the game calculates a hash and periodically compares it against expected value.
//    This detects various hooking methods (like replacing first few bytes of a function with a jump or patching vtables).
//    Normally the page hash table covers all mapped segments of the executable. Each entry is encrypted, and decrypted value is 0 for pages that aren't hashed.
//    First page (containing image header) is never hashed. So our workaround is simply setting number of pages to 1.
//    Other possible alternatives are:
//    - patching out the code that checks it - unfortunately, it's copies dozens of times, and it's annoying to track down all copies
//    - replacing each hash with zero - this is bad for performance, since then each check would iterate over entire table trying to find a page to check
//    - calculating new hashes after patching - this requires writing a fair amount of code, taking into account two (or three?) different hashing algorithms
// 2. For each segment the game stores the expected region properties and periodically does VirtualQuery and compares results with expected values.
//    This detects things like protection changes and remappings, and in general is annoying to deal with.
//    Current solution is to simply replace entries for all segments we touch with entries for segments we don't touch.
//    Other possible alternatives are:
//    - patching out the code that checks it - simple, although I'm not sure whether there are other copies of it (it's added to 'normal' functions)
//    - replacing expected values - requires inferring reverse algorithm, likely not hard
// 3. The page hash table itself is hashed, and there's a code in a dedicated tamper detection thread that checks it for tampering.
//    Since we're changing the size to 1, the calculated hash changes too.
//    Current solution is to patch the jump in the function to skip this check.
//    Other possible alternatives are:
//    - killing/permanently freezing the tamper detection thread - requires identifying it (it always runs tamper detection function, in an endless loop)
//    - fixing the expected hash - requires finding where the hash is stored and replicating hashing logic
// 4. The antitamper state itself is hashed, and there's a code in a dedicated tamper detection thread that checks it for tampering.
//    Since we're changing the size of the page hash table, which is stored in the region of the antitamper structure that is hashed, this needs fixing too.
//    Solutions are exactly same as for previous point.
// 5. The antitamper state contains two pointers that are normally mapped to same physical page, and there's a code that verifies that changing one affects the other.
//    This detects the remapping we do to enable protection change, which we need to be able to hook stuff.
//    Current solution is to patch the jump in the function to skip this check.
//    Other possible alternatives are:
//    - patch one of the pointers to point to the same memory as the other pointer - requires replicating encoding/decoding logic
//    - restore the mapping - also requires replicating at least decoding logic
export class AntiAntitamper
{
public:
	static AntiAntitamper& instance()
	{
		static AntiAntitamper inst;
		return inst;
	}

	void install()
	{
		auto& acc = AntitamperAccess::instance();
		if (acc.state()->dynState->pageHashCheckSpinlock())
			Log::msg("Warning: bad time to inject, antidebug thread is mid pagehash checks...");

		// pretend there's only 1 entry in page hash table
		auto key = acc.numPageHashesXorKey();
		auto& numPages = acc.state()->dynState->numPageHashes();
		Log::msg("Num hashed pages = {:X} == {:X} ^ {:X}", numPages ^ key, numPages, key);
		numPages = 1 ^ key;

		// avoid segment checks: replace first two (code and data) with last one
		auto* segments = acc.segments();
		segments[0] = segments[1] = segments[4];

		// skip checks in the antidebug thread, which validate tampering for antidebug state and pagehash map
		auto& hooker = App::instance().hooker();
		hooker.patchJumpToUnconditional(0x206C63); // page hash
		hooker.patchJumpToUnconditional(0x20721E); // state hash

		// skip memory mapping check
		hooker.patchJumpToUnconditional(0xEE1A55);
	}
};

// below can be used to hook some example spots to see pagehash in action:
//  patchHashDiff(imagebase, 0x15BAA80, 0x15BB54F);
//  patchHashDiff(imagebase, 0x16497A0, 0x1649700);
//
//void logHashDiff(u64 index, u32* table, u32 hash, u32 expected)
//{
//	auto& entry = table[1 + 2 * index];
//	auto hash_const = expected ^ entry;
//	Log::msg("hash difference found at #{:X} + {:X}: current={:08X}, expected={:08X}, hashed_expected={:08X}, hash_const={:08X}, f0={:08X}, e0={:08X}, table={}", index, 0x1000, hash, expected, entry, hash_const, table[0], table[1], static_cast<void*>(table));
//	entry = hash ^ hash_const;
//}
//
//void patchHashDiff(char* imagebase, u64 diffFoundRVA, u64 jumpRVA)
//{
//	// assumption: rbx = current hash, rax = expected hash, r13 = index, rdi = table
//	const unsigned char hashPatch[] = { 0x4C, 0x89, 0xE9, 0x48, 0x89, 0xFA, 0x41, 0x89, 0xD8, 0x41, 0x89, 0xC1, 0xFF, 0x15, 0x05, 0x00, 0x00, 0x00, 0xE9 };
//	memcpy(imagebase + diffFoundRVA, hashPatch, sizeof(hashPatch));
//	*(u32*)(imagebase + diffFoundRVA + sizeof(hashPatch)) = jumpRVA - diffFoundRVA - sizeof(hashPatch) - 4;
//	*(void**)(imagebase + diffFoundRVA + sizeof(hashPatch) + 4) = logHashDiff;
//}
