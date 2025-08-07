export module injected.cs.antitamper;

import common;
import injected.app;

// SC2 antitamper facilities have a delayed crash mechanism: if some tampering is detected, instead of crashing immediately, it sets some globals instead (including crash time, set to current time + random delay)
// every tick, it checks these globals and crashes if current time is larger than crash time
// crash state is encrypted (with key changing on every access) and protected by a spinlock
// blizzard devs care about reversers, so they've helpfully added a 'reason' field to the delayed crash state
// this is immediately followed by encryption key (u64) and then by spinlock (u32)
export struct DelayedCrashState
{
	u64 f0; // i don't think it's actually meaningful, it is not read anywhere as far as i can see, and changes randomly every time it's reencoded
	u64 crashTick; // if GetTickCount() returns >= this value, we crash
	u64 f10; // crash will happen if this is non-zero, usually some small int
	u32 f18;
	u32 reason;
	u64 f20; // crash will happen if this is non-zero, some sort of a hash?
	u64 f28;
};

// heap-allocated part of the antitamper state
// fields are all encoded, the algorithm is hardcoded everywhere it's accessed and uses some hardcoded constants - won't be surprised if they are different in every build
export struct AntitamperDynamic
{

};

// the main structure describing everything related to anti-tamper measures
// the instance is stored in .data section right after RTTI objects, easy to find
export struct AntitamperStatic
{
	u32 currentCrashReason; // usually 0, set to reason field when crash process starts; used to pass information to SEH filter or something
	AntitamperDynamic* dynState;
	void* pageHashMismatchCallback; // an optional callback executed when page hash mismatch is detected; it's null on runtime (some leftover debug thing?) and callers validate it's inside main code section
	bool flag0;
	bool flag1;
	bool flag2;
	bool flag3;
	bool flag4;
	bool flag5;
	bool flag6; // related to page hashing
	bool flag7; // related to page hashing
	bool pageHashUsesAVX2;

	// this is filled out by TLS callback, don't know whether it's used by something (some antidebug checks that detect injected threads maybe?)
	u32 knownThreadsSpinlock;
	u64 pad0;
	u64 knownThreads[256];

	u8 xorConstants[4096+8]; // these are used for decoding various things - u64's are read from here with random offsets in [0, 0xFFF] range

	u64 delayedCrashEncodedState[6];
	u64 delayedCrashEncryptionKey;
	u32 delayedCrashSpinlock;
};
static_assert(sizeof(AntitamperStatic) == 0x1878);

export class AntitamperAccess
{
public:
	static AntitamperAccess& instance()
	{
		static AntitamperAccess inst;
		return inst;
	}

	AntitamperStatic* staticData() const { return mPtr; }

	// various anti-tamper utilities use this transformation as part of its obfuscation process
	// it's symmetrical - calling it twice is identity transformation
	void obfuscate(u64& a1, u64& a2)
	{
		a2 = mObfuscation2 - a2;
		a1 ^= mObfuscation1;
	}

	DelayedCrashState decodeDelayedCrashState()
	{
		DelayedCrashState res = {};
		auto outPtr = &res.f0;
		u64 h1 = 0x96478FAEECCF46AE, h2 = mPtr->delayedCrashEncryptionKey;
		obfuscate(h1, h2);
		for (int i = 0; i < 6; ++i)
		{
			outPtr[i] = mPtr->delayedCrashEncodedState[i] ^ (std::rotr(h1, 11) - h2);
			h1 = std::rotr(mPtr->delayedCrashEncodedState[i], 11) - h2;
		}
		return res;
	}

private:
	AntitamperAccess()
	{
		// TODO: robust lookup method - maybe use TLS callback?..
		auto& hooker = App::instance().hooker();
		hooker.assign(0x39EEFC0, mPtr);

		const u64 c = 0xF3791823EBD0BA08;
		mObfuscation1 = ~reinterpret_cast<u64>(hooker.imagebase()) ^ c;
		mObfuscation2 = std::rotr(c, 12);
	}

private:
	AntitamperStatic* mPtr;
	u64 mObfuscation1 = 0;
	u64 mObfuscation2 = 0;
};
