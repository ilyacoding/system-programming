// Lab3ConsoleInjectMe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include <ostream>
#include <iostream>


int main()
{
	std::cout << "PID: " << GetCurrentProcessId() << std::endl;

	wchar_t oldString[] = L"Telegram";

	while(true)
	{
		std::wcout << oldString << std::endl;

		std::cin.get();
	}

	return 0;
}

