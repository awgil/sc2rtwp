module;

#include <common/win_headers.h>

export module common:pipe;

import std;
import :numeric;
import :ensure;
import :smart_handle;

// read-only (for now?)
export class PipeServer
{
public:
	// constructor blocks until connection happens
	PipeServer(const char* name, size_t bufferSize)
	{
		mPipe = CreateNamedPipeA(name, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, bufferSize, bufferSize, 0, nullptr);
		ensure(mPipe);

		const auto connected = ConnectNamedPipe(mPipe, nullptr);
		ensure(connected || GetLastError() == ERROR_PIPE_CONNECTED);
	}

	// blocks until message is received (returns num bytes read, > 0) or connection is broken (returns 0)
	u32 read(std::span<char> buffer)
	{
		DWORD nread = 0;
		if (!ReadFile(mPipe, buffer.data(), buffer.size_bytes(), &nread, nullptr) || !nread)
		{
			ensure(GetLastError() == ERROR_BROKEN_PIPE);
			return 0;
		}
		else
		{
			return nread;
		}
	}

private:
	SmartHandle mPipe;
};

// write-only (for now?)
// fallible
export class PipeClient
{
public:
	PipeClient(const char* name)
	{
		mPipe = CreateFileA(name, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	void write(std::span<char> buffer)
	{
		DWORD nwrite = 0;
		WriteFile(mPipe, buffer.data(), buffer.size_bytes(), &nwrite, nullptr);
	}

	explicit operator bool() const { return mPipe; }

private:
	SmartHandle mPipe;
};
