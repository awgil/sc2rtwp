module;

#include <common/win_headers.h>

export module injected.hooker;

import common;
import injected.logger;

// leaks memory, but that's fine, unhooking is hard
export class Hooker
{
public:
	Hooker(HMODULE module) : mImagebase(reinterpret_cast<char*>(module)) {}

	char* imagebase() const { return mImagebase; }

	char* alloc(size_t size)
	{
		if (mFree + size > mLimit)
		{
			mFree = static_cast<char*>(VirtualMemoryBlock(65536, PAGE_EXECUTE_READWRITE).leak());
			mLimit = mFree + 65536;
		}
		auto ptr = mFree;
		mFree = ptr + size;
		return ptr;
	}

	template<typename T> T* get(u64 rva) const
	{
		return reinterpret_cast<T*>(mImagebase + rva);
	}

	template<typename T> void assign(u64 rva, T*& outPtr) const
	{
		outPtr = get<T>(rva);
	}

	template<typename T> T* getRipRelative(u64 nextInstructionRVA) const
	{
		auto offset = *reinterpret_cast<i32*>(mImagebase + nextInstructionRVA - 4);
		return reinterpret_cast<T*>(mImagebase + nextInstructionRVA + offset);
	}

	template<typename T> void assignRipRelative(u64 nextInstructionRVA, T*& outPtr) const
	{
		outPtr = getRipRelative<T>(nextInstructionRVA);
	}

	// relocLen has to be >= 14
	template<typename T> T* hook(u64 rva, size_t relocLen, T* detour)
	{
		auto* func = mImagebase + rva;
		auto* original = alloc(relocLen + 6 + 8); // jmp [rip+0] + ptr
		memcpy(original, func, relocLen);
		*reinterpret_cast<u16*>(original + relocLen) = 0x25FF;
		*reinterpret_cast<u32*>(original + relocLen + 2) = 0;
		*reinterpret_cast<char**>(original + relocLen + 6) = func + relocLen;
		*reinterpret_cast<u16*>(func) = 0x25FF;
		*reinterpret_cast<u32*>(func + 2) = 0;
		*reinterpret_cast<void**>(func + 6) = detour;
		return reinterpret_cast<T*>(original);
	}

	void patchJumpToUnconditional(u64 rva)
	{
		auto* address = mImagebase + rva;
		if ((address[0] & 0xF0) == 0x70)
		{
			// near
			address[0] = 0xEB;
		}
		else if (address[0] == 0x0F && (address[1] & 0xF0) == 0x80)
		{
			address[0] = 0x90;
			address[1] = 0xE9;
		}
		else
		{
			Log::msg("Failed to patch jump at {}: {:02X}", address, address[0]);
		}
	}

private:
	char* mImagebase = nullptr;
	char* mFree = nullptr;
	char* mLimit = nullptr;
};
