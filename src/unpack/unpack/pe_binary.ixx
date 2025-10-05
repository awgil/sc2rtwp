module;

#include <common/win_headers.h>
#include <capstone/capstone.h>

export module unpack.pe_binary;

import std;
import common;
export import unpack.range_map;

export using va_t = uint64_t;
export using rva_t = int;

// simple utility for reading binary
class BinaryReader
{
public:
	BinaryReader(const char* path) : mStream(path, std::ios::binary) {}

	void readRaw(size_t offset, void* buffer, size_t size)
	{
		mStream.seekg(offset);
		mStream.read(static_cast<char*>(buffer), size);
	}

	template<typename T>
	T read(size_t offset)
	{
		T res;
		readRaw(offset, &res, sizeof res);
		return res;
	}

private:
	std::ifstream mStream;
};

// simple utility for writing binary
class BinaryWriter
{
public:
	BinaryWriter(const char* path) : mStream(path, std::ios::binary) {}

	void writeRaw(size_t offset, const void* buffer, size_t size)
	{
		mStream.seekp(offset);
		mStream.write(static_cast<const char*>(buffer), size);
	}

private:
	std::ofstream mStream;
};

// simple wrapper around capstone disassembler
class Disassembler
{
public:
	Disassembler()
	{
		ensure(cs_open(CS_ARCH_X86, CS_MODE_64, &mCapstone) == CS_ERR_OK);
		ensure(cs_option(mCapstone, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
		mInsn = cs_malloc(mCapstone);
		ensure(mInsn);
	}

	~Disassembler()
	{
		cs_free(mInsn, 1);
		ensure(cs_close(&mCapstone) == CS_ERR_OK);
	}

	// note: the returned pointer is only valid until next disasm call!
	cs_insn* disasm(const uint8_t* code, size_t size, size_t address) const
	{
		return cs_disasm_iter(mCapstone, &code, &size, &address, mInsn) ? mInsn : nullptr;
	}

	const char* instructionName(x86_insn isn) const { return cs_insn_name(mCapstone, isn); }
	const char* registerName(x86_reg reg) const { return cs_reg_name(mCapstone, reg); }

private:
	csh mCapstone = {};
	cs_insn* mInsn = nullptr;
};

// raw PE binary, that can parse headers and load sections at correct addresses - but does not parse contents of specific sections
class RawPEBinary
{
public:
	using Sections = NamedRangeMap<rva_t, IMAGE_SECTION_HEADER*, std::string_view>;
	using Section = Sections::Entry;

	RawPEBinary(const char* path)
	{
		BinaryReader source{ path };

		auto dosHeader = source.read<IMAGE_DOS_HEADER>(0);
		ensure(dosHeader.e_magic == IMAGE_DOS_SIGNATURE);

		auto peHeader = source.read<IMAGE_NT_HEADERS64>(dosHeader.e_lfanew);
		ensure(peHeader.Signature == IMAGE_NT_SIGNATURE);
		ensure(peHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
		ensure(peHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

		mBytes.resize(peHeader.OptionalHeader.SizeOfImage);
		source.readRaw(0, mBytes.data(), peHeader.OptionalHeader.SizeOfHeaders);

		initHeaders();

		for (auto& section : mSectionHeaders)
			source.readRaw(section.PointerToRawData, mBytes.data() + section.VirtualAddress, section.SizeOfRawData);

		auto& certEntry = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
		mCertBytes.resize(certEntry.Size);
		source.readRaw(certEntry.VirtualAddress, mCertBytes.data(), certEntry.Size);
	}

	void save(const char* path)
	{
		BinaryWriter writer{ path };
		writer.writeRaw(0, mBytes.data(), mPEHeader->OptionalHeader.SizeOfHeaders);
		for (auto& section : mSectionHeaders)
			writer.writeRaw(section.PointerToRawData, mBytes.data() + section.VirtualAddress, section.SizeOfRawData);

		auto& certEntry = mPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
		writer.writeRaw(certEntry.VirtualAddress, mCertBytes.data(), certEntry.Size);
	}

	auto& bytes() { return mBytes; }
	auto& peHeader() { return *mPEHeader; }
	auto sectionHeaders() { return mSectionHeaders; }
	auto& sections() { return mSections; }
	auto& certBytes() { return mCertBytes; }

	template<typename T> T* structAtRVA(rva_t rva) { return reinterpret_cast<T*>(mBytes.data() + rva); }

	va_t imageBase() const { return mPEHeader->OptionalHeader.ImageBase; }
	rva_t vaToRVA(va_t va) const { return static_cast<rva_t>(va - imageBase()); }
	rva_t entryPoint() const { return mPEHeader->OptionalHeader.AddressOfEntryPoint; }
	rva_t roundUpToFileAlignment(rva_t v) const { return (v + mPEHeader->OptionalHeader.FileAlignment - 1) & ~(mPEHeader->OptionalHeader.FileAlignment - 1); }

	const Section& section(size_t index) const { return mSections[index]; }

	// pretty print RVA
	std::string formatRVA(rva_t rva) const
	{
		return std::format("0x{:X} ({})", imageBase() + rva, mSections.formatOffset(rva, "imagebase"));
	}

protected:
	~RawPEBinary() = default; // should not be used directly

private:
	void initHeaders()
	{
		auto& dosHeader = reinterpret_cast<IMAGE_DOS_HEADER&>(mBytes[0]);
		mPEHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(&mBytes[dosHeader.e_lfanew]);
		mSectionHeaders = std::span<IMAGE_SECTION_HEADER>{ reinterpret_cast<IMAGE_SECTION_HEADER*>(mPEHeader + 1), mPEHeader->FileHeader.NumberOfSections };
		mSections.clear();
		for (auto& section : mSectionHeaders)
		{
			rva_t begin = section.VirtualAddress;
			rva_t end = begin + section.Misc.VirtualSize;
			auto name = reinterpret_cast<char*>(section.Name);
			// we assume sections are in order; if this assumption is broken, need to revise what 'section index' means (ie probably remove the section(index) accessor)
			mSections.insert({ begin, end, { name, strnlen(name, 8) }, &section }, mSections.end());
		}
	}

protected:
	std::vector<char> mBytes;
	IMAGE_NT_HEADERS64* mPEHeader;
	std::span<IMAGE_SECTION_HEADER> mSectionHeaders;
	Sections mSections;
	std::vector<char> mCertBytes;
};

// parsed SEH metadata
export class SEHInfo
{
public:
	struct Handler
	{
		rva_t rva; // 0 if no handlers
		SCOPE_TABLE* data;
	};
	using Entries = SimpleRangeMap<rva_t, Handler>;
	using Entry = typename Entries::Entry;

	SEHInfo(RawPEBinary& src)
	{
		auto& excDir = src.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		// TODO: ensure this fully covers .pdata section
		std::span sehEntries{ src.structAtRVA<RUNTIME_FUNCTION>(excDir.VirtualAddress), excDir.Size / sizeof(RUNTIME_FUNCTION) };
		ensure(sehEntries.size_bytes() == excDir.Size);

		for (auto& e : sehEntries)
		{
			auto& unwind = *src.structAtRVA<UNWIND_INFO>(e.UnwindData);
			ensure(unwind.Version == 1);
			if (unwind.Flags == UNW_FLAG_CHAININFO)
			{
				// if there are any subsequent chained entries, just extend the end address
				// note: usually for chained unwinds 'parent' is one of the previously defined entries; however, there are cases where parent is further down...
				// note: extend() checks that entry is not first and no gaps are created
				mEntries.extend(e.BeginAddress, e.EndAddress, mEntries.end());
			}
			else
			{
				constexpr auto handlerFlags = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER;
				ensure((unwind.Flags & ~handlerFlags) == 0); // other flag combinations are not expected for initial entry
				Handler h = {};
				if (unwind.Flags != 0)
				{
					auto handler = reinterpret_cast<rva_t*>(&unwind.UnwindCode[(unwind.CountOfCodes + 1) & ~1]);
					h.rva = *handler;
					h.data = reinterpret_cast<SCOPE_TABLE*>(handler + 1);
				}
				mEntries.insert({ static_cast<rva_t>(e.BeginAddress), static_cast<rva_t>(e.EndAddress), h }, mEntries.end());
			}
		}
	}

	const auto& sehEntries() const { return mEntries; }
	const Entry* findSEHEntry(rva_t rva) const { return mEntries.find(rva); }

protected:
	~SEHInfo() = default; // should not be used directly

private:
	Entries mEntries;
};

// parsed relocation metadata
class RelocInfo
{
public:
	RelocInfo(RawPEBinary& src)
	{
		auto& relDir = src.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		// TODO: ensure this fully covers .reloc section
		auto* relocStart = src.bytes().data() + relDir.VirtualAddress;
		auto* relocEnd = relocStart + relDir.Size;
		while (relocStart < relocEnd)
		{
			auto relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocStart);
			auto relocs = std::span<u16>{ reinterpret_cast<u16*>(relocBlock + 1), (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(u16) };
			relocStart += relocBlock->SizeOfBlock;
			for (auto reloc : relocs)
			{
				auto type = reloc >> 12;
				if (type == IMAGE_REL_BASED_DIR64)
					mRelocRVAs.push_back(relocBlock->VirtualAddress + (reloc & 0xFFF));
				else if (type != IMAGE_REL_BASED_ABSOLUTE)
					throw std::exception("Unsupported relocation type");
			}
		}
	}

	const auto& relocRVAs() const { return mRelocRVAs; }

protected:
	~RelocInfo() = default; // should not be used directly

private:
	std::vector<rva_t> mRelocRVAs; // sorted
};

// parsed TLS metadata
class TLSInfo
{
public:
	TLSInfo(RawPEBinary& src)
	{
		auto& tlsDir = src.peHeader().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		ensure(tlsDir.Size == sizeof(IMAGE_TLS_DIRECTORY));
		std::println("TLS directory at {}", src.formatRVA(tlsDir.VirtualAddress));
		mTLSDirEndRVA = tlsDir.VirtualAddress + tlsDir.Size;

		auto tlsRoot = src.structAtRVA<IMAGE_TLS_DIRECTORY>(tlsDir.VirtualAddress);
		auto tlsStartRVA = src.vaToRVA(tlsRoot->StartAddressOfRawData);
		auto tlsSize = tlsRoot->EndAddressOfRawData - tlsRoot->StartAddressOfRawData;
		auto tlsSection = src.sections().find(tlsStartRVA);
		ensure(tlsSection && tlsSection->name == ".tls" && tlsStartRVA == tlsSection->begin && src.roundUpToFileAlignment(tlsSize) == tlsSection->value->SizeOfRawData);

		auto tlsCallbacksRVA = src.vaToRVA(tlsRoot->AddressOfCallBacks);
		std::println("TLS callbacks at {}", src.formatRVA(tlsCallbacksRVA));
		while (true)
		{
			auto tlsCallbackVA = *src.structAtRVA<va_t>(tlsCallbacksRVA);
			if (!tlsCallbackVA)
				break;
			mCallbackRVAs.push_back(src.vaToRVA(tlsCallbackVA));
			tlsCallbacksRVA += sizeof(va_t);
		}
	}

	auto tlsDirEndRVA() const { return mTLSDirEndRVA; }
	const auto& tlsCallbackRVAs() const { return mCallbackRVAs; }

protected:
	~TLSInfo() = default; // should not be used directly

private:
	rva_t mTLSDirEndRVA = 0;
	std::vector<rva_t> mCallbackRVAs;
};

// full featured utility for interacting with PE binary
export class PEBinary : public RawPEBinary, public SEHInfo, public RelocInfo, public TLSInfo
{
public:
	PEBinary(const char* path)
		: RawPEBinary(path)
		, SEHInfo(static_cast<RawPEBinary&>(*this))
		, RelocInfo(static_cast<RawPEBinary&>(*this))
		, TLSInfo(static_cast<RawPEBinary&>(*this))
	{
	}

	// note: the returned pointer is only valid until next disasm call!
	cs_insn* disasm(rva_t rva) const
	{
		return mDisasm.disasm(reinterpret_cast<const uint8_t*>(mBytes.data() + rva), mBytes.size() - rva, imageBase() + rva);
	}

	const char* instructionName(x86_insn isn) const { return mDisasm.instructionName(isn); }
	const char* registerName(x86_reg reg) const { return mDisasm.registerName(reg); }

private:
	Disassembler mDisasm;
};
