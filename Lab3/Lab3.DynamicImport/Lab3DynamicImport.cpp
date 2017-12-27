// Lab3DynamicImport.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <iostream>

extern "C" typedef bool(_cdecl *ReplaceMemoryW)(const wchar_t *, const wchar_t *);

int main()
{
	wchar_t oldString[] = L"MyFirstString";

	HMODULE dll = LoadLibrary(L"../Debug/Lab3.Dll.dll");
	if (!dll)
	{
		std::cout << "Error";
		return -1;
	}

	std::wcout << oldString << std::endl;

	ReplaceMemoryW replace_memory = (ReplaceMemoryW)GetProcAddress(dll, "ReplaceMemoryW");

	replace_memory(L"MyFirstString", L"SmthElse");

	std::wcout << oldString << std::endl;

	FreeLibrary(dll);

	system("pause");

    return 0;
}

