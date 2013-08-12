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

#pragma once

struct RegistryWrapper
{
	LONG CloseKey(HKEY hKey);
	LONG ConnectRegistryA(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult);
	LONG CreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
	LONG CreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
	LONG OpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
	LONG OpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
	LONG QueryValueA(HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue);
	LONG QueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
	LONG SetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData);
	LONG SetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
};