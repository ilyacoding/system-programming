// Lab3StaticImport.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "Windows.h"
#include <ostream>
#include <iostream>

#include "../Lab3.Dll/lib.h"

int main()
{
	wchar_t string[] = L"MyRandomString";
	
	printf("%ws\n", string);

	ReplaceMemoryW(string, L"SomeSymbols");

	printf("%ws\n", string);

	system("pause");

	return 0;
}

