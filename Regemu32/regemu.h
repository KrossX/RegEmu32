/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <string>

namespace regemu
{
	LSTATUS close_key(HKEY hKey);
	LSTATUS create_key(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult, bool open);
	LSTATUS delete_key(HKEY hKey, LPCWSTR lpSubKey);
	LSTATUS delete_value(HKEY hKey, LPCWSTR lpValueName);
	LSTATUS enum_key(HKEY hKey, DWORD dwIndex, LPBYTE lpName, LPDWORD cchName, bool wide);
	LSTATUS flush_key(HKEY hKey);
	LSTATUS query_info_key(HKEY hKey, LPBYTE lpClass, LPDWORD lpcchClass, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime, bool wide);
	LSTATUS query_value_ex(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData, bool wide);
	LSTATUS set_value_ex(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, const BYTE *lpData, DWORD cbData, bool wide);
}

//#define LOG

#ifdef LOG
	#define WPRINTF(...) wprintf(__VA_ARGS__)
#else
	#define WPRINTF(...)
#endif