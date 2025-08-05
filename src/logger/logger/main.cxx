import std;
import common;

int main()
{
	char buffer[4096];
	while (true)
	{
		PipeServer pipe{ R"(\\.\pipe\sc2rtwp_log)", sizeof(buffer) };
		while (pipe.read(buffer))
		{
			std::println("{}", buffer);
		}
		std::println("Disconnected...");
	}
}
