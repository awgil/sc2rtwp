#include <common/win_headers.h>

import std;
import common;

//void dumpData(HANDLE process, uint64_t address, uint64_t size)
//{
//	auto buffer = (unsigned char*)_alloca(size);
//	size_t nread = 0;
//	ReadProcessMemory(process, (const void*)address, buffer, size, &nread);
//	for (int i = 0; i < size; ++i)
//	{
//		if (!(i & 0xF))
//			std::println("");
//		std::print("{:02X} ", buffer[i]);
//	}
//	std::println("");
//}

class ProtectSection : Nonmovable
{
public:
	ProtectSection(const Process& process, void* address, u32 protection, bool temporary = true)
		: mProc(process)
		, mInfo(process.queryMemoryInfo(address))
		, mTemporary(temporary)
	{
		mProc.remapMemory(mInfo.BaseAddress, mInfo.RegionSize, protection);
	}

	~ProtectSection()
	{
		if (mTemporary)
			mProc.protectMemory(mInfo.BaseAddress, mInfo.RegionSize, mInfo.Protect);
	}

	const auto& info() const { return mInfo; }
	void* sectionEnd() const { return static_cast<char*>(mInfo.BaseAddress) + mInfo.RegionSize; }

private:
	const Process& mProc;
	MEMORY_BASIC_INFORMATION mInfo;
	bool mTemporary;
};

class SuppressTLS : Nonmovable
{
public:
	SuppressTLS(const Process& process, HMODULE module)
		: mProcess(process)
	{
		auto imageBase = reinterpret_cast<char*>(module);
		auto dosHeader = process.readStruct<IMAGE_DOS_HEADER>(imageBase);
		auto ntHeader = process.readStruct<IMAGE_NT_HEADERS>(imageBase + dosHeader.e_lfanew);
		auto& tlsDir = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tlsDir.Size == 0)
			return;

		ensure(tlsDir.Size == sizeof(IMAGE_TLS_DIRECTORY));
		auto tlsHeader = process.readStruct<IMAGE_TLS_DIRECTORY>(imageBase + tlsDir.VirtualAddress);
		mTable = reinterpret_cast<void*>(tlsHeader.AddressOfCallBacks);
		mOriginal = process.readStruct<void*>(mTable);
		std::println("TLS callbacks at: {} -> {}", mTable, mOriginal);

		write(nullptr);
	}

	~SuppressTLS()
	{
		write(mOriginal);
	}

private:
	void write(void* address)
	{
		if (mTable && mOriginal)
			mProcess.writeStruct(mTable, address);
	}

private:
	const Process& mProcess;
	void* mTable = 0;
	void* mOriginal = 0;
};

std::wstring getFullPath(std::wstring filename)
{
	wchar_t buffer[4096];
	const auto len = ensure(GetModuleFileNameW(nullptr, buffer, ARRAYSIZE(buffer)));
	wcsrchr(buffer, L'\\')[1] = 0;
	return buffer + filename;
}

void injectLibrary(const Process& process, std::wstring library)
{
	const auto localKernel32 = ensure(GetModuleHandleA("kernel32.dll"));
	const auto remoteKernel32 = ensure(process.findModule("kernel32.dll"));
	auto getRemoteProcAddr = [&](const char* name) {
		const auto local = ensure(GetProcAddress(localKernel32, name));
		const auto offset = reinterpret_cast<const char*>(local) - reinterpret_cast<const char*>(localKernel32);
		return reinterpret_cast<const char*>(remoteKernel32) + offset;
	};

	VirtualMemoryBlock remoteCode(65536, PAGE_EXECUTE_READWRITE, process.handle());

	std::vector<unsigned char> code = {
		/* 0x00 */ 0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 ; needed for calling convention - we need to reserve at least 4 qwords for shadow args plus we need to align stack ptr to 0x10
		/* 0x04 */ 0x48, 0x8D, 0x0D, 0x21, 0x00, 0x00, 0x00, // lea rcx, [rip + 0x21] ; 0x2C - name of library to inject
		/* 0x0B */ 0xFF, 0x15, 0x0B, 0x00, 0x00, 0x00, // call [rip + 0xB] ; 0x1C - LoadLibrary
		/* 0x11 */ 0xFF, 0x15, 0x0D, 0x00, 0x00, 0x00, // call [rip + 0xD] ; 0x24 - GetLastError
		/* 0x17 */ 0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		/* 0x1B */ 0xC3, // ret
	};
	const auto dataOff = code.size();
	code.resize(dataOff + 16  + 2 * (library.length() + 1));
	*reinterpret_cast<const char**>(&code[dataOff]) = getRemoteProcAddr("LoadLibraryW");
	*reinterpret_cast<const char**>(&code[dataOff + 8]) = getRemoteProcAddr("GetLastError");
	memcpy(&code[dataOff + 16], library.c_str(), 2 * (library.length() + 1));
	process.writeMemory(remoteCode, code.size(), code.data());

	process.runCode(remoteCode);
}



//void overrideSpeed(HANDLE process, uint64_t address, uint32_t value)
//{
//	unsigned char buffer[] = { 0x48, 0x89, 0xC8, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC3 };
//	*(uint32_t*)(buffer + 5) = value;
//	size_t nwritten = 0;
//	WriteProcessMemory(process, (void*)address, buffer, sizeof(buffer), &nwritten);
//}

int main(int argc, char* argv[])
{
	bool realTarget = true;
	const auto proc = Process::findByName(realTarget ? "SC2_x64.exe" : "test_target.exe");
	const auto hprimary = proc.getPrimaryModule();

	ThreadSuspender suspend;
	suspend.suspendAll(proc);

	ProtectSection code{ proc, hprimary, PAGE_EXECUTE_READWRITE };
	ProtectSection data{ proc, code.sectionEnd(), PAGE_READWRITE, false }; // this is needed only for breakpoints...
	SuppressTLS suppressTls{ proc, hprimary };

	// patching...
	//uint64_t function = (uint64_t)hprimary + 0x1557580;
	//dumpData(proc.handle(), function, 0x30);

	injectLibrary(proc, getFullPath(L"sc2rtwp_in.dll"));

	//overrideSpeed(proc.handle(), function, 4096*16);
	// end patching...
}
