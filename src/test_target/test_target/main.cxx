import std;

bool stop = false;

int main()
{
	using namespace std::literals::chrono_literals;
	while (!stop)
		std::this_thread::sleep_for(1s);
}
