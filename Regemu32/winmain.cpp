/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include "regemu.h"
#include "registry.h"

//HINSTANCE h_instance = nullptr;

class console
{
public:
	console() { freopen("regemulog.txt", "w", stdout); }
	~console() { fclose(stdout); }
} pewpew;

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);
	BOOL result = TRUE;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		wprintf(L"%s: DLL_PROCESS_ATTACH (%d)\n", __FUNCTIONW__, fdwReason);
		break;

	case DLL_PROCESS_DETACH:
		wprintf(L"%s: DLL_PROCESS_DETACH (%d)\n", __FUNCTIONW__, fdwReason);
		break;
	}

	return result;
}