/*  RegEmu32 - Registry Operations on INI for Emulators
 *  Copyright (C) 2013  KrossX
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Windows.h>
#include "Wrapper.h"
#include <cstdio>
#include <string>

HINSTANCE g_hinstDLL = NULL;
RegistryWrapper reg;

#define _ENABLE_LOGFILE

#ifdef _ENABLE_LOGFILE
	FILE *logfile = NULL;
	#define LOG2FILE fprintf
#else
	#define LOG2FILE(...)
#endif



wchar_t fullnameINIw[MAX_PATH];
char    fullnameINIa[MAX_PATH];

bool GetINIfilename()
{
	bool good;

	good  = (GetModuleFileNameA(g_hinstDLL, fullnameINIa, MAX_PATH) > 0) && GetLastError() == ERROR_SUCCESS;
	good &= (GetModuleFileNameW(g_hinstDLL, fullnameINIw, MAX_PATH) > 0) && GetLastError() == ERROR_SUCCESS;


	if(good)
	{
		std::string  filenameA(fullnameINIa);
		std::wstring filenameW(fullnameINIw);

		filenameA = filenameA.substr(0, filenameA.find_last_of("\\/"));
		filenameW = filenameW.substr(0, filenameW.find_last_of(L"\\/"));

		sprintf_s(fullnameINIa, "%s\\Regemu32.INI", filenameA.c_str());
		swprintf_s(fullnameINIw, L"%s\\Regemu32.INI", filenameW.c_str());
	}

	return good;
}


extern "C" BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )
{
	UNREFERENCED_PARAMETER(lpReserved);
	BOOL result = TRUE;

	switch( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		{
		#ifdef _ENABLE_LOGFILE
			if(!logfile) fopen_s(&logfile, "Regemu32.log", "w");
		#endif
			g_hinstDLL =  hinstDLL;
			result = GetINIfilename() ? TRUE : FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		{
		#ifdef _ENABLE_LOGFILE
			if(logfile) fclose(logfile);
			logfile = NULL;
		#endif
		}
		break;
	}

	return result;
}

char* GetKeyString(HKEY key)
{
	switch((DWORD)key)
	{
	case 0x80000000: return "HKEY_CLASSES_ROOT";
	case 0x80000001: return "HKEY_CURRENT_USER";
	case 0x80000002: return "HKEY_LOCAL_MACHINE";
	case 0x80000003: return "HKEY_USERS";
	case 0x80000004: return "HKEY_PERFORMANCE_DATA";
	case 0x80000005: return "HKEY_CURRENT_CONFIG";
	case 0x80000006: return "HKEY_DYN_DATA";
	case 0x80000007: return "HKEY_CURRENT_USER_LOCAL_SETTINGS";
	case 0x80000050: return "HKEY_PERFORMANCE_TEXT";
	case 0x80000060: return "HKEY_PERFORMANCE_NLSTEXT";
	default: return "";
	}
}

char *GetTypeString(DWORD type)
{
	switch(type)
	{
	case 0x00: return "REG_NONE";
	case 0x01: return "REG_SZ";
	case 0x02: return "REG_EXPAND_SZ";
	case 0x03: return "REG_BINARY";
	case 0x04: return "REG_DWORD_LITTLE_ENDIAN";
	case 0x05: return "REG_DWORD_BIG_ENDIAN";
	case 0x06: return "REG_LINK";
	case 0x07: return "REG_MULTI_SZ";
	case 0x08: return "REG_RESOURCE_LIST";
	case 0x09: return "REG_FULL_RESOURCE_DESCRIPTOR";
	case 0x0A: return "REG_RESOURCE_REQUIREMENTS_LIST";
	case 0x0B: return "REG_QWORD_LITTLE_ENDIAN";
	default: return "";
	}
}


struct REGKEY
{
	char key[256];
	DWORD type;
	void *self;
};

bool IsGoodKey(HKEY key)
{
	bool good = false;

	if(key)
	{
		REGKEY *rk = (REGKEY*)key;
		if(rk->self == rk) good = true;
	}

	return good;
}

LONG RegistryWrapper::CloseKey(HKEY hKey)
{
	bool good = IsGoodKey(hKey);

	if(good)
	{
		REGKEY *rk = (REGKEY*)hKey;
		delete rk;
		rk = NULL;
	}

	//LOG2FILE(logfile, "%s: %08X | %s\n", __FUNCTION__, hKey, good? "Good" : "Bad");
	
	return good? ERROR_SUCCESS : -1;
}

LONG RegistryWrapper::ConnectRegistryA(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult)
{
	REGKEY *rkey = new REGKEY();

	sprintf_s(rkey->key, "%s", GetKeyString(hKey));

	rkey->self = rkey;

	*phkResult = (HKEY)rkey;

	//LOG2FILE(logfile, "%s: %s, %s (%08X)\n", __FUNCTION__, lpMachineName, GetKeyString(hKey), *phkResult);

	return ERROR_SUCCESS;
}

LONG RegistryWrapper::CreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return -1;
}

LONG RegistryWrapper::CreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return -1;
}

LONG RegistryWrapper::OpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	REGKEY *keyin = (REGKEY*)hKey;
	

	bool good = IsGoodKey(hKey);

	if(good)
	{
		REGKEY *keyout = new REGKEY();

		sprintf_s(keyout->key, "%s\\%s", keyin->key, lpSubKey);

		keyout->self = keyout;

		*phkResult = (HKEY)keyout;
	}

	//LOG2FILE(logfile, "%s: %08X, %s (%08X)\n", __FUNCTION__, hKey, lpSubKey, *phkResult);

	return good? ERROR_SUCCESS : -1;
}

LONG RegistryWrapper::OpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return -1;
}

LONG RegistryWrapper::QueryValueA(HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return -1;
}

LONG RegistryWrapper::QueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	REGKEY *key = (REGKEY*)hKey;
	bool good = IsGoodKey(hKey);
	

	if(good)
	{
		char *value_new = NULL;
		size_t value_len = lpValueName? strlen(lpValueName) : 0;

		if(value_len > 0)
		{
			value_len += 4;
			value_new = new char[value_len];
			sprintf_s(value_new, value_len, "\"%s\"", lpValueName);
		}
		else
		{
			value_new = new char[10];
			sprintf_s(value_new, 10, "(default)");
		}

		size_t buffer_len = lpcbData? (*lpcbData * 3 + 6) : 512;
		char* buffer = new char[buffer_len];

		DWORD length = GetPrivateProfileStringA(key->key, value_new, "", buffer, buffer_len, fullnameINIa);
		good = GetLastError() == ERROR_SUCCESS;

		if(good && lpData && lpcbData && *lpcbData > 0)
		{
			strcpy_s((char*)lpData, *lpcbData, buffer);
			*lpcbData = strlen((char*)lpData);
		}

		if(lpType) *lpType = 0x02;

		if(buffer) delete[] buffer;
		if(value_new) delete[] value_new;
	}

	LOG2FILE(logfile, "%s: %08X, %s, %08X, %08X, %08X\n", __FUNCTION__, hKey, lpValueName, lpType, lpData, lpcbData ? *lpcbData : 0);
	return good? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
}

LONG RegistryWrapper::SetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return -1;
}

LONG RegistryWrapper::SetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	REGKEY *key = (REGKEY*)hKey;
	bool good = IsGoodKey(hKey);

	if(good)
	{
		char *value_new = NULL;
		char *data_new = NULL;

		size_t value_len = lpValueName ? strlen(lpValueName) : 0;

		if(value_len > 0)
		{
			value_len += 4;
			value_new = new char[value_len];
			sprintf_s(value_new, value_len, "\"%s\"", lpValueName);
		}
		else
		{
			value_new = new char[10];
			sprintf_s(value_new, 10, "(default)");
		}

		if(cbData && lpData)
		{
			switch(dwType)
			{
			case 0x01: //REG_SZ
				cbData += 4;
				data_new = new char[cbData];
				sprintf_s(data_new, cbData, "\"%s\"", lpData);
				break;

			case 0x02: //REG_EXPAND_SZ
			case 0x03: //REG_BINARY
			case 0x04: //REG_DWORD_LITTLE_ENDIAN
			case 0x05: //REG_DWORD_BIG_ENDIAN
			case 0x06: //REG_LINK
			case 0x07: //REG_MULTI_SZ
			case 0x08: //REG_RESOURCE_LIST
			case 0x09: //REG_FULL_RESOURCE_DESCRIPTOR
			case 0x0A: //REG_RESOURCE_REQUIREMENTS_LIST
			case 0x0B: //REG_QWORD_LITTLE_ENDIAN
			default: break;
			}
		}

		WritePrivateProfileStringA(key->key, value_new, data_new, fullnameINIa);

		if(data_new) delete[] data_new;
		if(value_new) delete[] value_new;
	}

	LOG2FILE(logfile, "%s: %08X, %s, %s, %08X, %08X\n", __FUNCTION__, hKey, lpValueName, GetTypeString(dwType), lpData, cbData);
	return ERROR_SUCCESS;
}
