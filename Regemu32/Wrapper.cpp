/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include "regemu.h"

static LPCWSTR atow(LPCSTR in)
{
	static std::wstring wide;

	std::string ansi(in ? in : "");
	wide = std::wstring(ansi.length(), L'');
	std::copy(ansi.begin(), ansi.end(), wide.begin());
	return wide.c_str();
}

LSTATUS WINAPI reg_close_key(HKEY hKey)
{
	//return RegCloseKey(hKey);
	return regemu::close_key(hKey);
}

LSTATUS WINAPI reg_connect_registry_a(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult)
{
	//return RegConnectRegistryA(lpMachineName, hKey, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, true);
}

LSTATUS WINAPI reg_connect_registry_ex_a(LPCSTR lpMachineName, HKEY hKey, ULONG Flags, PHKEY phkResult)
{
	//return RegConnectRegistryExA(lpMachineName, hKey, Flags, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, true);
}

LSTATUS WINAPI reg_connect_registry_ex_w(LPCWSTR lpMachineName, HKEY hKey, ULONG Flags, PHKEY phkResult)
{
	//return RegConnectRegistryExW(lpMachineName, hKey, Flags, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, true);
}

LSTATUS WINAPI reg_connect_registry_w(LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult)
{
	//return RegConnectRegistryW(lpMachineName, hKey, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, true);
}

LSTATUS WINAPI reg_create_key_a(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	//return RegCreateKeyA(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, false);
}

LSTATUS WINAPI reg_create_key_ex_a(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	//return RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, false);
}

LSTATUS WINAPI reg_create_key_ex_w(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	//return RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	return regemu::create_key(hKey, lpSubKey, phkResult, false);
}

LSTATUS WINAPI reg_create_key_w(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
	//return RegCreateKeyW(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, false);
}

LSTATUS WINAPI reg_delete_key_a(HKEY hKey, LPCSTR lpSubKey)
{
	//return RegDeleteKeyA(hKey, lpSubKey);
	return regemu::delete_key(hKey, atow(lpSubKey));
}

LSTATUS WINAPI reg_delete_key_w(HKEY hKey, LPCWSTR lpSubKey)
{
	//return RegDeleteKeyW(hKey, lpSubKey);
	return regemu::delete_key(hKey, lpSubKey);
}

LSTATUS WINAPI reg_delete_value_a(HKEY hKey, LPCSTR lpValueName)
{
	//return RegDeleteValueA(hKey, lpValueName);
	return regemu::delete_value(hKey, atow(lpValueName));
}

LSTATUS WINAPI reg_delete_value_w(HKEY hKey, LPCWSTR lpValueName)
{
	//return RegDeleteValueW(hKey, lpValueName);
	return regemu::delete_value(hKey, lpValueName);
}

LSTATUS WINAPI reg_enum_key_a(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName)
{
	//return RegEnumKeyA(hKey, dwIndex, lpName, cchName);
	return regemu::enum_key(hKey, dwIndex, (LPBYTE)lpName, &cchName, false);
}

LSTATUS WINAPI reg_enum_key_ex_a(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
	//return RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
	return regemu::enum_key(hKey, dwIndex, (LPBYTE)lpName, lpcchName, false);
}

LSTATUS WINAPI reg_enum_key_ex_w(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
	//return RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
	return regemu::enum_key(hKey, dwIndex, (LPBYTE)lpName, lpcchName, true);
}

LSTATUS WINAPI reg_enum_key_w(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName)
{
	//return RegEnumKeyW(hKey, dwIndex, lpName, cchName);
	return regemu::enum_key(hKey, dwIndex, (LPBYTE)lpName, &cchName, true);
}

LSTATUS WINAPI reg_flush_key(HKEY hKey)
{
	//return RegFlushKey(hKey);
	return regemu::flush_key(hKey);
}

LSTATUS WINAPI reg_open_key_a(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	//return RegOpenKeyA(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, true);
}

LSTATUS WINAPI reg_open_key_ex_a(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	//return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, true);
}

LSTATUS WINAPI reg_open_key_ex_w(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	//return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, true);
}

LSTATUS WINAPI reg_open_key_w(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
	//return RegOpenKeyW(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, true);
}

LSTATUS WINAPI reg_query_info_key_a(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)
{
	//return RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
	return regemu::query_info_key(hKey, (LPBYTE)lpClass, lpcchClass, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime, false);
}

LSTATUS WINAPI reg_query_info_key_w(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)
{
	//return RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
	return regemu::query_info_key(hKey, (LPBYTE)lpClass, lpcchClass, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime, true);
}

LSTATUS WINAPI reg_query_value_a(HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)
{
	//return RegQueryValueA(hKey, lpSubKey, lpValue, lpcbValue);
	return regemu::query_value_ex(hKey, atow(lpSubKey), nullptr, nullptr, (LPBYTE)lpValue, (LPDWORD)lpcbValue, false);
}

LSTATUS WINAPI reg_query_value_ex_a(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	//return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	return regemu::query_value_ex(hKey, nullptr, atow(lpValueName), lpType, lpData, lpcbData, false);
}

LSTATUS WINAPI reg_query_value_ex_w(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	//return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	return regemu::query_value_ex(hKey, nullptr, lpValueName, lpType, lpData, lpcbData, true);
}

LSTATUS WINAPI reg_query_value_w(HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue)
{
	//return RegQueryValueW(hKey, lpSubKey, lpValue, lpcbValue);
	return regemu::query_value_ex(hKey, lpSubKey, nullptr, nullptr, (LPBYTE)lpValue, (LPDWORD)lpcbValue, true);
}

LSTATUS WINAPI reg_set_value_a(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)
{
	//return RegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
	return regemu::set_value_ex(hKey, atow(lpSubKey), nullptr, dwType, (LPBYTE)lpData, cbData, false);
}

LSTATUS WINAPI reg_set_value_ex_a(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	//return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	return regemu::set_value_ex(hKey, nullptr, atow(lpValueName), dwType, lpData, cbData, false);
}

LSTATUS WINAPI reg_set_value_ex_w(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	//return RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	return regemu::set_value_ex(hKey, nullptr, lpValueName, dwType, lpData, cbData, true);
}

LSTATUS WINAPI reg_set_value_w(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)
{
	//return RegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
	return regemu::set_value_ex(hKey, lpSubKey, nullptr, dwType, (LPBYTE)lpData, cbData, true);
}

// PASSTHROUGH

BOOL WINAPI adjust_token_privileges(HANDLE a, BOOL b, PTOKEN_PRIVILEGES c, DWORD d, PTOKEN_PRIVILEGES e, PDWORD f)
{ return AdjustTokenPrivileges(a, b, c, d, e, f); }

BOOL WINAPI allocate_and_initialize_sid(PSID_IDENTIFIER_AUTHORITY a, BYTE b, DWORD c, DWORD d, DWORD e, DWORD f, DWORD g, DWORD h, DWORD i, DWORD j, PSID *k)
{ return AllocateAndInitializeSid(a, b, c, d, e, f, g, h, i, j, k); }

BOOL WINAPI check_token_membership(HANDLE a, PSID b, PBOOL c)
{ return CheckTokenMembership(a, b, c); }

BOOL WINAPI equal_sid(PSID a, PSID b)
{ return EqualSid(a, b); }

PVOID WINAPI free_sid(PSID a)
{ return FreeSid(a); }

BOOL WINAPI get_token_information(HANDLE a, TOKEN_INFORMATION_CLASS b, LPVOID c, DWORD d, PDWORD e)
{ return GetTokenInformation(a, b, c, d, e); }

BOOL WINAPI get_user_name_a(LPSTR lpBuffer, LPDWORD pcbBuffer)
{ return GetUserNameA(lpBuffer, pcbBuffer); }

BOOL WINAPI get_user_name_w(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{ return GetUserNameW(lpBuffer, pcbBuffer); }

BOOL WINAPI lookup_privilege_value_w(LPCWSTR a, LPCWSTR b, PLUID c)
{ return LookupPrivilegeValueW(a, b, c); }

BOOL WINAPI open_process_token(HANDLE a, DWORD b, PHANDLE c)
{ return OpenProcessToken(a, b, c); }

BOOL WINAPI open_thread_token(HANDLE a, DWORD b, BOOL c, PHANDLE d)
{ return OpenThreadToken(a, b, c, d); }
