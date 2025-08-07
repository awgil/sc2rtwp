#pragma once

/* Macro to define common bitfield operations for enums. */
#define ADD_BITFIELD_OPS(enumname) \
	inline constexpr enumname operator~(enumname arg) { return (enumname)(~(int)arg); } \
	inline constexpr enumname operator|(enumname lhs, enumname rhs) { return (enumname)((int)lhs | (int)rhs); } \
	inline constexpr enumname operator&(enumname lhs, enumname rhs) { return (enumname)((int)lhs & (int)rhs); } \
	inline void operator|=(enumname &lhs, enumname rhs) { lhs = lhs | rhs; } \
	inline void operator&=(enumname &lhs, enumname rhs) { lhs = lhs & rhs; }
