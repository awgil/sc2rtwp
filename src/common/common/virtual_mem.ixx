module;

#include <common/win_headers.h>

export module common:virtual_mem;

import std;
import :noncopyable;
import :numeric;
import :ensure;

// RAII wrapper around piece of memory
// if allocated in remote process, the process should outlive the block
export class VirtualMemoryBlock : Noncopyable
{
public:
	VirtualMemoryBlock(size_t size, u32 protection, HANDLE process = INVALID_HANDLE_VALUE)
		: mProcess(process)
		, mPtr(VirtualAllocEx(mProcess, nullptr, size, MEM_RESERVE | MEM_COMMIT, protection))
	{
		ensure(mPtr);
	}

	VirtualMemoryBlock(VirtualMemoryBlock&& rhs)
		: mProcess(rhs.mProcess)
		, mPtr(rhs.mPtr)
	{
		rhs.mPtr = nullptr;
	}

	VirtualMemoryBlock& operator=(VirtualMemoryBlock&& rhs)
	{
		clear();
		mProcess = rhs.mProcess;
		mPtr = rhs.mPtr;
		rhs.mPtr = nullptr;
		return *this;
	}

	~VirtualMemoryBlock()
	{
		clear();
	}

	operator void* () const { return mPtr; }

	void* leak()
	{
		auto p = mPtr;
		mPtr = nullptr;
		return p;
	}

private:
	void clear()
	{
		if (mPtr)
		{
			VirtualFreeEx(mProcess, mPtr, 0, MEM_RELEASE);
			mPtr = nullptr;
		}
	}

private:
	HANDLE mProcess = INVALID_HANDLE_VALUE;
	void* mPtr = nullptr;
};
