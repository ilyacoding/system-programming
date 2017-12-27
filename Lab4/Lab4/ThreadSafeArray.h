#pragma once
#include <vector>
#include <Windows.h>

class ThreadSafeArray
{
private:
	CRITICAL_SECTION CriticalSection;
	std::vector<std::vector<std::string>> _array;

public:
	ThreadSafeArray()
	{
		InitializeCriticalSection(&CriticalSection);
	}

	void Add(std::vector<std::string> v)
	{
		EnterCriticalSection(&CriticalSection);

		_array.push_back(v);

		LeaveCriticalSection(&CriticalSection);
	}

	std::vector<std::vector<std::string>> Get()
	{
		return _array;
	}
};
