#pragma once

/* Macro to define common bitfield operations for enums. */
#define ADD_BITFIELD_OPS(enumname) \
	inline constexpr enumname operator~(enumname arg) { return static_cast<enumname>(~std::to_underlying(arg)); } \
	inline constexpr enumname operator|(enumname lhs, enumname rhs) { return static_cast<enumname>(std::to_underlying(lhs) | std::to_underlying(rhs)); } \
	inline constexpr enumname operator&(enumname lhs, enumname rhs) { return static_cast<enumname>(std::to_underlying(lhs) & std::to_underlying(rhs)); } \
	inline constexpr enumname operator^(enumname lhs, enumname rhs) { return static_cast<enumname>(std::to_underlying(lhs) ^ std::to_underlying(rhs)); } \
	inline void operator|=(enumname &lhs, enumname rhs) { lhs = lhs | rhs; } \
	inline void operator&=(enumname &lhs, enumname rhs) { lhs = lhs & rhs; } \
	inline void operator^=(enumname &lhs, enumname rhs) { lhs = lhs ^ rhs; }
