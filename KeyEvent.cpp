#include "stdafx.h"
#include <Windows.h>

HINSTANCE hinst;
HHOOK hhk;

typedef void (*Keypress)(WPARAM);
Keypress keypress = (Keypress) GetProcAddress(GetModuleHandle(L"TraderTravelMod.dll"), "keypress");

unsigned int i = 0;
LRESULT CALLBACK wireKeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
	if (!(lParam & (1 << 30)) && ++i % 2 == 0)
	{
		keypress(wParam);
	}
	
	return CallNextHookEx(hhk, code, wParam, lParam);
}

extern "C" __declspec(dllexport) void install() {
	hhk = SetWindowsHookEx(WH_KEYBOARD, wireKeyboardProc, hinst, NULL);
}
extern "C" __declspec(dllexport) void uninstall() {
	UnhookWindowsHookEx(hhk);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved	) {
	hinst = hinstDLL;
	return TRUE;
}
