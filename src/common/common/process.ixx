module;

#include <common/win_headers.h>

export module common:process;

import std;
import :noncopyable;
import :numeric;
import :ensure;
import :smart_handle;
import :requery;
import :virtual_mem;

// utilities for working with processes
// static functions allow various queries, class instance represents an opened process handle
export class Process
{
public:
	// enumerate id's of all running processes
	static std::vector<DWORD> enumerate()
	{
		// note: unfortunately, EnumProcesses doesn't return actual size on overrun, so just retry with ever growing buffer until success
		return requery<DWORD>(1024, [](std::span<DWORD> res) {
			DWORD written = 0;
			ensure(EnumProcesses(res.data(), res.size_bytes(), &written));
			return written < res.size_bytes() ? written / sizeof(DWORD) : res.size() * 2;
		});
	}

	static Process findByName(std::string_view name)
	{
		char buffer[2048];
		for (Process proc : Process::enumerate())
		{
			if (!proc)
				continue; // failed to open, skip
			auto procName = proc.getImageFileName(buffer);
			if (procName.length() > name.length() && procName.ends_with(name) && procName[procName.length() - name.length() - 1] == '\\')
				return proc;
		}
		return {};
	}

	static MEMORY_BASIC_INFORMATION queryMemoryInfoFor(const void* address, HANDLE handle = INVALID_HANDLE_VALUE)
	{
		MEMORY_BASIC_INFORMATION meminfo = {};
		ensure(VirtualQueryEx(handle, address, &meminfo, sizeof(meminfo)));
		return meminfo;
	}

	Process() = default; // default-constructed process with id=0 represents a null state

	Process(u32 id)
		: mId(id)
		, mHandle(OpenProcess(PROCESS_ALL_ACCESS, false, id))
	{
	}

	auto id() const { return mId; }
	HANDLE handle() const { return mHandle; }
	explicit operator bool() const { return mHandle; }

	std::string_view getImageFileName(std::span<char> buffer) const
	{
		const auto len = ensure(GetProcessImageFileNameA(mHandle, buffer.data(), buffer.size()));
		return { buffer.data(), len};
	}

	HMODULE getPrimaryModule() const
	{
		// assumption: primary module is always first
		HMODULE handle;
		DWORD needed = 0;
		ensure(EnumProcessModulesEx(mHandle, &handle, sizeof(handle), &needed, LIST_MODULES_64BIT));
		ensure(needed);
		return handle;
	}

	std::vector<HMODULE> enumerateModules() const
	{
		return requery<HMODULE>(0, [this](std::span<HMODULE> res) {
			DWORD written = 0;
			ensure(EnumProcessModulesEx(mHandle, res.data(), res.size_bytes(), &written, LIST_MODULES_64BIT));
			return written / sizeof(HMODULE);
		});
	}

	std::string_view getModuleBaseName(HMODULE module, std::span<char> buffer) const
	{
		const auto len = ensure(GetModuleBaseNameA(mHandle, module, buffer.data(), buffer.size()));
		return { buffer.data(), len };
	}

	HMODULE findModule(std::string_view name) const
	{
		char buffer[2048];
		for (auto module : enumerateModules())
		{
			auto cur = getModuleBaseName(module, buffer);
			if (name.length() == cur.length()  && !strnicmp(cur.data(), name.data(), name.length()))
				return module;
		}
		return nullptr;
	}

	std::vector<u32> enumerateThreads() const
	{
		std::vector<u32> res;
		SmartHandle snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, mId);
		ensure(snapshot);
		THREADENTRY32 thread = { sizeof(THREADENTRY32) };
		for (auto success = Thread32First(snapshot, &thread); success; success = Thread32Next(snapshot, &thread))
		{
			if (thread.th32OwnerProcessID == mId)
			{
				res.push_back(thread.th32ThreadID);
			}
		}
		return res;
	}

	SmartHandle createThread(void* entryPoint) const
	{
		DWORD threadId = 0;
		SmartHandle thread = ensure(CreateRemoteThread(mHandle, nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(entryPoint), nullptr, CREATE_SUSPENDED, &threadId));
		ResumeThread(thread);
		return thread;
	}

	// spawn a thread to execute code, wait for completion and return exit code
	u32 runCode(void* entryPoint) const
	{
		auto thread = createThread(entryPoint);
		WaitForSingleObject(thread, INFINITE);
		DWORD exitCode = 0;
		ensure(GetExitCodeThread(thread, &exitCode));
		return exitCode;
	}

	MEMORY_BASIC_INFORMATION queryMemoryInfo(const void* address) const
	{
		return queryMemoryInfoFor(address, mHandle);
	}

	void readMemory(const void* address, size_t size, void* buffer) const
	{
		ensure(ReadProcessMemory(mHandle, address, buffer, size, nullptr));
	}

	template<typename T> T readStruct(const void* address) const
	{
		T res;
		readMemory(address, sizeof(T), &res);
		return res;
	}

	void writeMemory(void* address, size_t size, const void* buffer) const
	{
		ensure(WriteProcessMemory(mHandle, address, buffer, size, nullptr));
	}

	template<typename T> void writeStruct(void* address, const T& v) const
	{
		writeMemory(address, sizeof(T), &v);
	}

	void protectMemory(void* address, size_t size, u32 protection) const
	{
		DWORD prev = 0;
		ensure(VirtualProtectEx(mHandle, address, size, protection, &prev));
	}

	void remapMemory(void* address, size_t size, u32 protection) const
	{
		// save existing data
		VirtualMemoryBlock copy{ size, PAGE_READWRITE };
		readMemory(address, size, copy);

		// create replacement section
		HANDLE section = nullptr;
		LARGE_INTEGER sectionMaxSize{ .QuadPart = static_cast<i64>(size) };
		ensure(NtCreateSection(&section, SECTION_ALL_ACCESS, nullptr, &sectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr) == STATUS_SUCCESS);

		// unmap old section
		ensure(NtUnmapViewOfSection(mHandle, address) == STATUS_SUCCESS);

		// and map the replacement in its place
		SIZE_T viewSize = 0;
		ensure(NtMapViewOfSection(section, mHandle, &address, 0, size, nullptr, &viewSize, ViewUnmap, 0, protection) == STATUS_SUCCESS);

		// finally restore saved data into newly mapped view
		writeMemory(address, size, copy);
	}

private:
	u32 mId = 0;
	SmartHandle mHandle; // note: can be null, if we don't have permissions to open the process
};

// utility to suspend threads, and automatically resume on destruction
export class ThreadSuspender : Noncopyable
{
public:
	~ThreadSuspender()
	{
		for (auto& thread : mSuspendedThreads)
			ResumeThread(thread);
	}

	void suspend(u32 threadId)
	{
		auto h = ensure(OpenThread(THREAD_ALL_ACCESS, false, threadId));
		SuspendThread(h);
		mSuspendedThreads.push_back(std::move(h));
	}

	void suspendAll(const Process& proc)
	{
		// TODO: this currently might miss a thread that's spawned while this is running
		// this is not a big concern in practice, since apps we're injecting into don't spawn threads often on runtime
		// theoretically, we can build a system that requeries again until no new threads are found, and then assume no one spawns remote threads...
		for (auto id : proc.enumerateThreads())
			suspend(id);
	}

private:
	std::vector<SmartHandle> mSuspendedThreads;
};
