export module common:log;

import std;
import :numeric;

// simplistic logger
// more detailed levels are expected to compare greater than less detailed
export template<typename Level> class Logger
{
public:
	Logger(std::string name, Level level) : mName(std::move(name)), mLevel(level) {}

	template<typename... Args>
	void operator()(Level level, std::format_string<Args...> fmt, Args&&... args)
	{
		if (level > mLevel)
			return;
		std::print("[{}] ", mName);
		std::println(fmt, std::forward<Args>(args)...);
	}

	void setLevel(Level level) { mLevel = level; }
	Level level() const { return mLevel; }

private:
	std::string mName;
	Level mLevel;
};

// utility to log recursion level with flag per level
export struct NestingTracker
{
	u32 cur = 0;
	u32 next = 1; // mask with single bit set, corresponding to next push

	NestingTracker push(bool value = false) const { return { cur | (value ? next : 0), next << 1 }; }
	NestingTracker pop() const { return { cur & ~next, next >> 1 }; }
};

export template<> struct std::formatter<NestingTracker>
{
	constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

	auto format(const NestingTracker& obj, format_context& ctx) const
	{
		for (u32 m = 1; m != obj.next; m <<= 1)
			*ctx.out() = obj.cur & m ? '+' : '-';
		return ctx.out();
	}
};
