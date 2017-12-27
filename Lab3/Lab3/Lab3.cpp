// Lab3.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <ostream>
#include <iostream>
#include <Windows.h>


int main()
{
	std::cout << "PID: " << GetCurrentProcessId() << std::endl;

	char oldString[] = "OLD_STRING";

	std::cout << oldString << std::endl;

	std::cin.get();

	std::cout << oldString << std::endl;

	return 0;
}
