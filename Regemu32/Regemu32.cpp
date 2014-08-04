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

//#define _ENABLE_LOGFILE

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

char *KeyString[] =
{
	"HKEY_CLASSES_ROOT",
	"HKEY_CURRENT_USER",
	"HKEY_LOCAL_MACHINE",
	"HKEY_USERS",
	"HKEY_PERFORMANCE_DATA",
	"HKEY_CURRENT_CONFIG",
	"HKEY_DYN_DATA",
	"HKEY_CURRENT_USER_LOCAL_SETTINGS",
	"HKEY_PERFORMANCE_TEXT",
	"HKEY_PERFORMANCE_NLSTEXT",
	""
};

char* GetKeyString(HKEY key)
{
	switch((DWORD)key)
	{
	case 0x80000000: return KeyString[0x00];
	case 0x80000001: return KeyString[0x01];
	case 0x80000002: return KeyString[0x02];
	case 0x80000003: return KeyString[0x03];
	case 0x80000004: return KeyString[0x04];
	case 0x80000005: return KeyString[0x05];
	case 0x80000006: return KeyString[0x06];
	case 0x80000007: return KeyString[0x07];
	case 0x80000050: return KeyString[0x08];
	case 0x80000060: return KeyString[0x09];
	default:		 return KeyString[0x0A];;
	}
}

char *TypeString[] = 
{
	"REG_NONE",
	"REG_SZ",
	"REG_EXPAND_SZ",
	"REG_BINARY",
	"REG_DWORD_LITTLE_ENDIAN",
	"REG_DWORD_BIG_ENDIAN",
	"REG_LINK",
	"REG_MULTI_SZ",
	"REG_RESOURCE_LIST",
	"REG_FULL_RESOURCE_DESCRIPTOR",
	"REG_RESOURCE_REQUIREMENTS_LIST",
	"REG_QWORD_LITTLE_ENDIAN",
	""
};

char *GetTypeString(DWORD type)
{
	switch(type)
	{
	case 0x00:	return TypeString[0x00];
	case 0x01:	return TypeString[0x01];
	case 0x02:	return TypeString[0x02];
	case 0x03:	return TypeString[0x03];
	case 0x04:	return TypeString[0x04];
	case 0x05:	return TypeString[0x05];
	case 0x06:	return TypeString[0x06];
	case 0x07:	return TypeString[0x07];
	case 0x08:	return TypeString[0x08];
	case 0x09:	return TypeString[0x09];
	case 0x0A:	return TypeString[0x0A];
	case 0x0B:	return TypeString[0x0B];
	default:	return TypeString[0x0C];;
	}
}

struct REGKEY
{
	std::string key, subkey;
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

	LOG2FILE(logfile, "%s: %08X | %s\n", __FUNCTION__, hKey, good? "Good" : "Bad");
	return good? ERROR_SUCCESS : -1;
}

LONG RegistryWrapper::ConnectRegistryA(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult)
{
	REGKEY *rkey = new REGKEY();

	rkey->key = std::string(GetKeyString(hKey));
	rkey->self = rkey;

	*phkResult = (HKEY)rkey;

	//LOG2FILE(logfile, "%s: %s, %s (%08X)\n", __FUNCTION__, lpMachineName, rkey->key.c_str(), *phkResult);

	return ERROR_SUCCESS;
}

LONG RegistryWrapper::CreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return OpenKeyA(hKey, lpSubKey, phkResult);
}

LONG RegistryWrapper::CreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	LOG2FILE(logfile, "%s\n", __FUNCTION__, lpdwDisposition);

	LONG result = CreateKeyA(hKey, lpSubKey, phkResult);
	bool isNewKey = true;

	if(result == ERROR_SUCCESS)
	{
		REGKEY *key = (REGKEY*)*phkResult;

		std::string section(key->key);
		section.append("\\").append(key->subkey);

		FILE *ini = NULL;
		fopen_s(&ini, fullnameINIa, "r");

		if(ini)
		{
			char linebuffer[256];

			while(!feof(ini) && isNewKey)
			{
				fgets(linebuffer, 256, ini);

				if(linebuffer[0] == '[')
					isNewKey = !!strncmp(&linebuffer[1], section.c_str(), section.length());
			}

			fclose(ini);
		}
	}

	if(lpdwDisposition)
		*lpdwDisposition = isNewKey ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;

	return result;
}

LONG RegistryWrapper::OpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	DWORD keytest = (DWORD)hKey;

	if(keytest == (0x80000007 & keytest))
		ConnectRegistryA(NULL, hKey, &hKey);

	REGKEY *keyin = (REGKEY*)hKey;
	
	bool good = IsGoodKey(hKey);

	if(good)
	{
		if (lpSubKey && !(*lpSubKey))
		{
			*phkResult = hKey;
		}
		else
		{
			REGKEY *keyout = new REGKEY();
			keyout->key = keyin->key;
			keyout->subkey = keyin->subkey;
			keyout->self = keyout;

			if (lpSubKey)
				keyout->subkey.append("\\").append(lpSubKey);

			*phkResult = (HKEY)keyout;
		}
	}

	LOG2FILE(logfile, "%s: %08X, %s (%08X)\n", __FUNCTION__, hKey, lpSubKey, *phkResult);
	return good? ERROR_SUCCESS : -1;
}

LONG RegistryWrapper::OpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	//LOG2FILE(logfile, "%s\n", __FUNCTION__);
	return OpenKeyA(hKey, lpSubKey, phkResult);
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
		DWORD type = 0;

		std::string value_new("(default)");
		size_t value_len = lpValueName? strlen(lpValueName) : 0;

		if(value_len > 0)
			value_new = std::string("\"").append(lpValueName).append("\"");

		size_t buffer_len = lpcbData? (*lpcbData * 3 + 6) : 512;
		char* buffer = new char[buffer_len];

		std::string section(key->key);

		if (key->subkey[0] == '\\')
			section.append(key->subkey);
		else
			section.append("\\").append(key->subkey);
		
		DWORD length = GetPrivateProfileStringA(section.c_str(), value_new.c_str(), "", buffer, buffer_len, fullnameINIa);
		good = GetLastError() == ERROR_SUCCESS;

		LOG2FILE(logfile, "%s: %s || %s || %s\n", __FUNCTION__, section.c_str(), value_new.c_str(), fullnameINIa);

		if(good && lpData && lpcbData && *lpcbData > 0)
		{
			
			if(strncmp(buffer, "dword:", 6) == 0) // REG_DWORD_LITTLE_ENDIAN
			{
				DWORD data = strtol(&buffer[6], NULL, 16);
				memcpy(lpData, &data, 4);
				type = 0x04;
			}
			else // REG_SZ
			{
				strcpy_s((char*)lpData, *lpcbData, buffer);
				*lpcbData = strlen((char*)lpData);
				type = 0x01;
			}
		}

		if(lpType) *lpType = type;
		if(buffer) delete[] buffer;
	}

	LOG2FILE(logfile, "%s: %08X, %s, %08X, %08X, %08X | %s\n", __FUNCTION__, hKey, lpValueName, lpType ? *lpType : 0, lpData, lpcbData ? *lpcbData : 0, good? "Good" : "Bad");
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
		std::string value_new("(default)");
		
		size_t value_len = lpValueName ? strlen(lpValueName) : 0;

		if(value_len > 0)
			value_new = std::string("\"").append(lpValueName).append("\"");

		char *data_new = NULL;

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
				break;

			case 0x04: //REG_DWORD_LITTLE_ENDIAN
				data_new = new char[15];
				sprintf_s(data_new, 15, "dword:%08X", *(DWORD*)lpData);
				break;

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

		std::string section(key->key);
		section.append("\\").append(key->subkey);

		WritePrivateProfileStringA(section.c_str(), value_new.c_str(), data_new, fullnameINIa);

		if(data_new) delete[] data_new;
	}

	LOG2FILE(logfile, "%s: %08X, %s, %s, %08X, %08X\n", __FUNCTION__, hKey, lpValueName, GetTypeString(dwType), lpData, cbData);
	return ERROR_SUCCESS;
}
