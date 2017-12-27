#pragma once
#include <Windows.h>
#include "Queue.h"
#include "ThreadSafeArray.h"

class ThreadsHandler
{
	Queue _queue;
	int threads_amount;
public:
	ThreadSafeArray array;
	HANDLE* hThreads;

	ThreadsHandler(Queue queue, int threads)
	{
		threads_amount = threads;
		hThreads = new HANDLE[threads];
		_queue = queue;
	}
	
	static DWORD WINAPI SortWorker(LPVOID lpParam) {
		auto This = (ThreadsHandler*)lpParam;

		auto task = This->_queue.Pop();
		if (task.size() > 0)
		{
			std::sort(task.begin(), task.end());

			This->array.Add(task);
		}

		ExitThread(0);
	}

	ThreadSafeArray Process()
	{
		for (int i = 0; i < threads_amount; i++)
		{
			hThreads[i] = CreateThread(nullptr, 0, SortWorker, (LPVOID)this, 0, nullptr);
		}

		for (int i = 0; i < threads_amount; i++)
		{
			WaitForSingleObject(hThreads[i], INFINITE);
		}

		return array;
	}
};
