module;

#include <common/win_headers.h>

export module common:smart_handle;

import std;
import :noncopyable;

// RAII wrapper around win32 HANDLE that needs to be closed.
// Note that there is some API inconsistency in the value of "invalid" handle - sometimes it is 0, sometimes it is -1 (INVALID_HANDLE_VALUE).
// This class tries to deal with it by silently converting -1 to 0 on construction.
// This has the side-effect, however: -1 is also used as a "pseudohandle" for things like current process handle.
// It is thus incorrect to wrap pseudohandles into smart_handle. This shouldn't be a very big deal, since pseudohandles don't need to be closed,
// and generally the caller can semantically distinguish between real and pseudo handles.
export class SmartHandle : Noncopyable
{
public:
	SmartHandle() = default;
	SmartHandle(HANDLE h) : mHandle(h != INVALID_HANDLE_VALUE ? h : nullptr) {}
	SmartHandle(SmartHandle&& rhs) : mHandle(rhs.mHandle) { rhs.mHandle = nullptr; }
	SmartHandle& operator=(SmartHandle&& rhs) { std::swap(mHandle, rhs.mHandle); return *this; }

	~SmartHandle()
	{
		if (mHandle)
			CloseHandle(mHandle);
	}

	operator HANDLE() const { return mHandle; }
	explicit operator bool() const { return mHandle != nullptr; }

private:
	HANDLE mHandle = nullptr;
};
