// Lab2Table.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Lab2Table.h"

#define MAX_LOADSTRING 100

HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

// VARS
#define ROWS 4
#define COLUMNS 3

wchar_t* blocks[ROWS][COLUMNS] = {
	{ L"—ъешь этих м€гких французских булочек, да выпей чаю.", L"Eat these soft French rolls, but have some tea.", L"—ъешь этих м€гких французских булочек, да выпей чаю. —ъешь этих м€гких французских булочек, да выпей чаю." },
	{ L"Eat these soft French rolls, but have some tea.", L"—ъешь этих м€гких французских булочек, да выпей чаю. —ъешь этих м€гких французских булочек, да выпей чаю.", L"Eat these soft French rolls, but have some tea." },
	{ L"—ъешь этих м€гких французских булочек, да выпей чаю.", L"Eat these soft French rolls, but have some tea.", L"—ъешь этих м€гких французских булочек, да выпей чаю." },
	{ L"Eat these soft French rolls, but have some tea.Eat these soft French rolls, but have some tea.Eat these soft French rolls, but have some tea.", L"—ъешь этих м€гких французских булочек, да выпей чаю.", L"Eat these soft French rolls, but have some tea." },
};

RECT rect;
POINT pt;
HFONT font;
HFONT hFontOld;

const UINT DRAWTEXT_WORDS = DT_WORDBREAK | DT_WORD_ELLIPSIS;
const int delta = 2;

int fontSize;

int width;
int windowHeight;

float horizontalStep;
// VARS

// FUNCTIONS
void DrawVerticalTableLines(HDC hdc);
float DrawTextInTable(HDC hdc, bool calculating);
// FUNCTIONS

// Events
void OnCreate();
void OnPaint(HWND hWnd);
void OnSize(HWND hWnd);
void OnGetMinMaxInfo(LPARAM & lParam);
// Events

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_LAB2TABLE, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LAB2TABLE));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LAB2TABLE));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_LAB2TABLE);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
   
   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
	case WM_CREATE:
		OnCreate();
		break;
    case WM_PAINT:
		OnPaint(hWnd);
        break;
	case WM_GETMINMAXINFO:
		OnGetMinMaxInfo(lParam);
		break;
	case WM_SIZE:
		OnSize(hWnd);
		break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

void OnCreate()
{
	font = CreateFont(fontSize, 0, 0, 0, 0, false, false, false, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Monaco");
}

void OnGetMinMaxInfo(LPARAM & lParam)
{
	const auto lpMmi = reinterpret_cast<LPMINMAXINFO>(lParam);
	lpMmi->ptMinTrackSize.x = 100;
	lpMmi->ptMinTrackSize.y = 100;
}

void FontSizeCalculate(HDC hdc)
{
	fontSize = 15;

	while (windowHeight - DrawTextInTable(hdc, true) > 10)
	{
		fontSize++;
	}

	while (DrawTextInTable(hdc, true) > windowHeight)
	{
		fontSize--;
	}
}

void OnPaint(HWND hWnd)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hWnd, &ps);

	FontSizeCalculate(hdc);

	DrawTextInTable(hdc, 0);
	DrawVerticalTableLines(hdc);

	EndPaint(hWnd, &ps);
}

void OnSize(HWND hWnd)
{
	if (GetClientRect((HWND)hWnd, &rect))
	{
		width = rect.right - rect.left;
		windowHeight = rect.bottom - rect.top;
		horizontalStep = width / COLUMNS;

		InvalidateRect(hWnd, nullptr, true);
	}
}

void DrawVerticalTableLines(HDC hdc)
{
	for (float i = horizontalStep; i < width - delta; i += horizontalStep)
	{
		MoveToEx(hdc, i, 0, &pt);
		LineTo(hdc, i, windowHeight);
	}
}

void DrawHorizontalTableLine(HDC hdc, float maxHeight)
{
	MoveToEx(hdc, 0, maxHeight, &pt);
	LineTo(hdc, width, maxHeight);
}

float GetTextHeight(HDC hdc, wchar_t* string, float leftBorder, float rightBorder)
{
	RECT rect;
	rect.left = leftBorder;
	rect.right = rightBorder;
	rect.top = 0;

	DrawText(hdc, string, -1, &rect, DT_CALCRECT | DRAWTEXT_WORDS);

	return rect.bottom;
}

void CreateFontWithSize(int fontSize)
{
	font = CreateFont(fontSize, 0, 0, 0, 0, false, false, false, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, nullptr);
}

float DrawRows(HDC hdc, UINT drawTextKeywords, bool calculating)
{
	float startingOffset = 0;

	CreateFontWithSize(fontSize);
	hFontOld = (HFONT)SelectObject(hdc, font);

	for (int i = 0; i < ROWS; i++)
	{
		int maxHeight = INT_MIN;

		for (int j = 0; j < COLUMNS; j++)
		{
			RECT textRect(rect);

			textRect.left = j * horizontalStep + delta;
			textRect.right = (j + 1) * horizontalStep - delta;
			textRect.top = startingOffset + delta;
			textRect.bottom = textRect.top + GetTextHeight(hdc, blocks[i][j], textRect.left, textRect.right);

			if (textRect.bottom > maxHeight)
			{
				maxHeight = textRect.bottom;
			}

			DrawText(hdc, blocks[i][j], -1, &textRect, drawTextKeywords);
		}

		startingOffset = maxHeight;

		if (!calculating && i != ROWS - 1)
		{
			DrawHorizontalTableLine(hdc, maxHeight);
		}
	}

	SelectObject(hdc, hFontOld);
	DeleteObject(font);

	return startingOffset;
}

float DrawTextInTable(HDC hdc, bool calcSize)
{
	UINT drawTextKeywords = DRAWTEXT_WORDS;

	if (calcSize)
	{
		drawTextKeywords |= DT_CALCRECT;
	}

	return DrawRows(hdc, drawTextKeywords, calcSize);
}
