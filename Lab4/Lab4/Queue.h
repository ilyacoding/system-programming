#pragma once
#include <string>
#include <queue>
#include "Windows.h"
#include <iostream>

class Queue
{
private:
	CRITICAL_SECTION CriticalSection;
	std::queue<std::vector<std::string>> _queue;

public:
	Queue()
	{
		InitializeCriticalSection(&CriticalSection);
	}

	Queue(std::vector<std::vector<std::string>> tasks)
	{
		InitializeCriticalSection(&CriticalSection);

		for (SIZE_T i = 0; i < tasks.size(); i++)
		{
			Push(tasks[i]);
		}
	}

	bool Empty()
	{
		return _queue.size() == 0;
	}

	void Push(std::vector<std::string> vector)
	{
		EnterCriticalSection(&CriticalSection);

		_queue.push(vector);

		LeaveCriticalSection(&CriticalSection);
	}

	std::vector<std::string> Pop()
	{
		EnterCriticalSection(&CriticalSection);

		std::vector<std::string> element;

		if (_queue.size() > 0)
		{
			element = _queue.front();
			_queue.pop();
		}

		LeaveCriticalSection(&CriticalSection);
		
		return element;
	}
};
