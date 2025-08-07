module;

#include <common/bitfield_ops.h>
#include <common/win_headers.h>

export module injected.app;

import std;
import common;
import injected.logger;
import injected.hooker;

export enum class Modifier : u8
{
	None = 0,
	Shift = 1 << 0,
	Ctrl = 1 << 1,
	Alt = 1 << 2,
};
ADD_BITFIELD_OPS(Modifier);

export struct Keybind
{
	u8 key = 0;
	Modifier mod = Modifier::None;
	bool press = false; // if true, keybind activates on press rather than on release

	bool operator==(const Keybind&) const = default;
	bool operator!=(const Keybind&) const = default;
};

template<> struct std::hash<Keybind>
{
	std::size_t operator()(const Keybind& k) const noexcept
	{
		return std::hash<u32>{}(k.key | (static_cast<u32>(k.mod) << 8) | (static_cast<u32>(k.press) << 16));
	}
};

// the primary entry point for interacting with injected app
// provides a way to hook functions and use common services (like tick callbacks, keybinds, etc).
export class App
{
public:
	static App& instance()
	{
		static App inst;
		return inst;
	}

	Hooker& hooker() { return mHooker; }
	char* imagebase() const { return mHooker.imagebase(); }

	void installHooks()
	{
		// hook main tick function
		oriTick = mHooker.hook(0x15BF4B0, 0x13, hookTick);
		oriWndproc = mHooker.hook(0x24CAF0, 0xF, hookWndproc);
	}

	// add a callback to be executed every following tick, until it returns true
	void addTickCallback(std::function<bool()>&& cbk)
	{
		mTickCallbacks.push_back(std::move(cbk));
	}

	void addKeybind(Keybind key, std::function<void()>&& action)
	{
		mKeybinds[key] = std::move(action);
	}

private:
	App() : mHooker(ensure(GetModuleHandleA(nullptr))) {}

	void processKeyEvent(u8 vk, bool down)
	{
		switch (vk)
		{
		case VK_SHIFT:
		case VK_LSHIFT:
		case VK_RSHIFT:
			changeModifierState(Modifier::Shift, down);
			break;
		case VK_CONTROL:
		case VK_LCONTROL:
		case VK_RCONTROL:
			changeModifierState(Modifier::Ctrl, down);
			break;
		case VK_MENU:
		case VK_LMENU:
		case VK_RMENU:
			changeModifierState(Modifier::Alt, down);
			break;
		default:
			if (auto it = mKeybinds.find(Keybind{ vk, mHeldModifiers, down }); it != mKeybinds.end())
				it->second();
			break;
		}
	}

	void changeModifierState(Modifier mod, bool down)
	{
		if (down)
			mHeldModifiers |= mod;
		else
			mHeldModifiers &= ~mod;
	}

private:
	bool (*oriTick)() = nullptr;
	static bool hookTick()
	{
		auto& inst = instance();
		auto [delFirst, delLast] = std::ranges::remove_if(inst.mTickCallbacks, [](const auto& cbk) { return cbk(); });
		inst.mTickCallbacks.erase(delFirst, delLast);
		return inst.oriTick();
	}

	LRESULT(*oriWndproc)(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) = nullptr;
	static LRESULT hookWndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
	{
		auto& inst = instance();
		switch (msg)
		{
		case WM_KEYDOWN:
			if ((lparam >> 30) == 0) // bit 30 == 1 means that key was already held
				inst.processKeyEvent(wparam, true);
			break;
		case WM_KEYUP:
			inst.processKeyEvent(wparam, false);
			break;
		}
		return inst.oriWndproc(hwnd, msg, wparam, lparam);
	}

private:
	Hooker mHooker;
	std::vector<std::function<bool()>> mTickCallbacks;
	Modifier mHeldModifiers;
	std::unordered_map<Keybind, std::function<void()>> mKeybinds;
};
