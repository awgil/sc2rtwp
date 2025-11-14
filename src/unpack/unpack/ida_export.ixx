module;

#include <rfl.hpp>

#include "../../../thirdparty/reflect-cpp/include/rfl/fields.hpp"
#include "../../../thirdparty/reflect-cpp/include/rfl/Literal.hpp"

export module unpack.ida_export;

export import std;
export import common;

export class IDAExporter
{
	static constexpr i64 imagebase = 0x140000000;

public:
	IDAExporter(const std::filesystem::path& path)
		: mOutput(path)
	{
		raw("import idaapi");
		raw("import ida_funcs");
		raw("import ida_name");
		raw("import ida_struct");
		raw("import ida_typeinf");
		raw("");
		raw("def process_func(begin, end, name):");
		raw("    func = ida_funcs.get_func(begin)");
		raw("    if not func:");
		raw("        print(f'Function {name} at {begin:X} does not exist, creating...')");
		raw("        ida_funcs.add_func(begin, end)");
		raw("        func = ida_funcs.get_func(begin)");
		raw("        if not func:");
		raw("            print(f'>> FAILED!')");
		raw("            return");
		raw("    if func.start_ea != begin:");
		raw("        print(f'Function {name} at {begin:X} has unexpected start {func.start_ea:X}')");
		raw("        return");
		raw("    if func.end_ea != end:");
		raw("        print(f'Function {name} at {begin:X} has unexpected end {func.end_ea:X} rather than {end:X}')");
		raw("    if name:");
		raw("        ida_name.set_name(func.start_ea, name)");
		raw("");
		raw("def process_global(ea, type, name):");
		raw("    ida_name.set_name(ea, name)");
		raw("    if not type:");
		raw("        return");
		raw("    tif = ida_typeinf.tinfo_t()");
		raw("    if not ida_typeinf.parse_decl(tif, None, type + ';', 0) == '':");
		raw("        print(f'Failed to parse type {type} for global at {ea:X}')");
		raw("        return");
		raw("    if not ida_typeinf.apply_tinfo(ea, tif, 0):");
		raw("        print(f'Failed to apply type {type} to global at {ea:X}')");
		raw("");
	}

	void registerFunction(i32 begin, i32 end, std::string_view name)
	{
		emit("process_func(0x{:X}, 0x{:X}, '{}')", imagebase + begin, imagebase + end, name);
	}

	void registerGlobalName(i32 rva, std::string_view name)
	{
		emit("process_global(0x{:X}, '', '{}')", imagebase + rva, name);
	}

	template<typename T> void registerGlobal(i32 rva, std::string_view name)
	{
		emit("process_global(0x{:X}, '{}', '{}')", imagebase + rva, rfl::type_name_t<T>().name(), name);
	}

private:
	void raw(std::string_view str)
	{
		mOutput << str << std::endl;
	}

	template<typename... Args>
	void emit(std::format_string<Args...> fmt, Args&&... args)
	{
		std::println(mOutput, fmt, std::forward<Args>(args)...);
	}

private:
	std::ofstream mOutput;
};
