// Lab2.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Lab1.h"
#include <string>
#include "resource.h"
#include "DrawingObject.h"

#define MAX_LOADSTRING 100

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

const int ACCELERATE_TIMER = 1;

HBITMAP hBitmap = NULL;

DrawingObject *drawingObject = new DrawingObject();

RECT rect;
int height;
int width;

DWORD WINAPI draw_func(LPVOID hWnd)
{
	while (true)
	{
		if (drawingObject->isMoving())
		{
			drawingObject->Move(height, width);
			InvalidateRect((HWND)hWnd, NULL, TRUE);
			UpdateWindow((HWND)hWnd);
		}
		Sleep(20);
	}
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_LAB1, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LAB1));

	MSG msg;

	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}


ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LAB1));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_LAB1);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

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

	SetTimer(hWnd, ACCELERATE_TIMER, 100, (TIMERPROC)NULL);
	CreateThread(NULL, 0, draw_func, (LPVOID)hWnd, 0, 0);

	return TRUE;
}

void UpdateWindowSize(HWND hWnd);
void LoadAndBlitBitmap(HDC hWinDC);

void OnCreate(HWND);
LRESULT OnCommand(HWND, UINT, WPARAM, LPARAM);
void OnTimer(WPARAM);
void OnAccelerateTimer();
void OnKeyDown(WPARAM);
void OnMouseWheel(WPARAM);
void OnKeyUp(WPARAM);
void OnPaint(HWND);
void OnSize(HWND);

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_CREATE:
			OnCreate(hWnd);
			break;
		case WM_COMMAND:
			return OnCommand(hWnd, message, wParam, lParam);
			break;
		case WM_TIMER:
			OnTimer(wParam);
			break;
		case WM_KEYDOWN:
			OnKeyDown(wParam);
			break;

		case WM_MOUSEWHEEL:
			OnMouseWheel(wParam);
			break;

		case WM_KEYUP:
			OnKeyUp(wParam);
			break;

		case WM_PAINT:
			OnPaint(hWnd);
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

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

void UpdateWindowSize(HWND hWnd)
{
	if (GetClientRect((HWND)hWnd, &rect))
	{
		width = rect.right - rect.left;
		height = rect.bottom - rect.top;
	}
}

void LoadAndBlitBitmap(HDC hWinDC)
{
	HDC hLocalDC;
	hLocalDC = CreateCompatibleDC(hWinDC);

	BITMAP qBitmap;
	GetObject(reinterpret_cast<HGDIOBJ>(hBitmap), sizeof(BITMAP), reinterpret_cast<LPVOID>(&qBitmap));

	HBITMAP hOldBmp = (HBITMAP)::SelectObject(hLocalDC, hBitmap);

	BitBlt(hWinDC, drawingObject->x1, drawingObject->y1, qBitmap.bmWidth, qBitmap.bmHeight, hLocalDC, 0, 0, SRCCOPY);
	SelectObject(hLocalDC, hOldBmp);
	DeleteDC(hLocalDC);
}

void OnCreate(HWND hWnd)
{
	UpdateWindowSize(hWnd);
	BITMAP qBitmap;
	hBitmap = (HBITMAP)LoadImage(NULL, __T("apple.bmp"), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
	GetObject(reinterpret_cast<HGDIOBJ>(hBitmap), sizeof(BITMAP), reinterpret_cast<LPVOID>(&qBitmap));
	drawingObject->SetSize(qBitmap.bmHeight, qBitmap.bmWidth);
}

LRESULT OnCommand(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId = LOWORD(wParam);
	switch (wmId)
	{
	case IDM_ABOUT:
		DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
		break;
	case IDM_EXIT:
		DestroyWindow(hWnd);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
}

void OnTimer(WPARAM wParam)
{
	switch (wParam)
	{
	case ACCELERATE_TIMER:
		OnAccelerateTimer();
		break;
	}
}

void OnAccelerateTimer()
{
	drawingObject->Accelerate();
}

void OnKeyDown(WPARAM wParam)
{
	switch (wParam)
	{
	case VK_UP:
		drawingObject->StartKeyPress(UP);
		break;
	case VK_DOWN:
		drawingObject->StartKeyPress(DOWN);
		break;
	case VK_LEFT:
		drawingObject->StartKeyPress(LEFT);
		break;
	case VK_RIGHT:
		drawingObject->StartKeyPress(RIGHT);
		break;
	}
}

void OnKeyUp(WPARAM wParam)
{
	switch (wParam)
	{
	case VK_UP:
		drawingObject->StopKeyPress(UP);
		break;
	case VK_DOWN:
		drawingObject->StopKeyPress(DOWN);
		break;
	case VK_LEFT:
		drawingObject->StopKeyPress(LEFT);
		break;
	case VK_RIGHT:
		drawingObject->StopKeyPress(RIGHT);
		break;
	}
}

void OnMouseWheel(WPARAM wParam)
{
	int fwKeys = GET_KEYSTATE_WPARAM(wParam);
	int zDelta = GET_WHEEL_DELTA_WPARAM(wParam);

	bool shiftPressed = fwKeys == MK_SHIFT;

	if (zDelta > 0)
	{
		if (shiftPressed)
		{
			drawingObject->WheelScroll(RIGHT);
		}
		else
		{
			drawingObject->WheelScroll(UP);
		}
	}
	else if (zDelta < 0)
	{
		if (shiftPressed)
		{
			drawingObject->WheelScroll(LEFT);
		}
		else
		{
			drawingObject->WheelScroll(DOWN);
		}
	}
}

void OnPaint(HWND hWnd)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hWnd, &ps);
	//Ellipse(hdc, drawingObject->x1, drawingObject->y1, drawingObject->x2, drawingObject->y2);
	LoadAndBlitBitmap(hdc);
	EndPaint(hWnd, &ps);
}

void OnSize(HWND hWnd)
{
	UpdateWindowSize(hWnd);
}
