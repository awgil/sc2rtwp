#include <common/win_headers.h>

import common;
import injected.logger;
import injected.hooker;
import injected.app;
import injected.antiantitamper;
import injected.debug.veh;
import injected.debug.stack_protect;
import injected.debug.delayed_crash;
import injected.debug.trigger_ids;
import injected.game.slowmode;
import injected.game.rtwp;

void init()
{
	auto& app = App::instance();
	Log::msg("Hello from injected; imagebase = {}", static_cast<void*>(app.imagebase()));
	app.installHooks();

	// deactivate anti-tampering measures that we care about
	AntiAntitamper::instance().install();

	// debug stuff - should be possible to disable completely and still run this
	DebugVEH::instance().install();
	DebugStackProtect::instance().installMainThread();
	DebugDelayedCrash::instance().installTickMonitor();
	DebugDelayedCrash::instance().installChangeMonitor();
	//DebugTriggerIds::instance().install();

	GameSlowmode::instance().install();
	GameRTWP::instance().install();
	Log::msg("Injection done, resuming game...");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		init();
	}
	return true;
}
