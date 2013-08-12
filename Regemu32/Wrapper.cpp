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

#include "Windows_Mini.h"
#include "Wrapper.h"

extern RegistryWrapper reg;


extern "C" LONG WINAPI RegCloseKey(
  _In_  HKEY hKey
)
{
	return reg.CloseKey(hKey);
}

extern "C" LONG WINAPI RegConnectRegistryA(
  _In_opt_  LPCSTR lpMachineName,
  _In_      HKEY hKey,
  _Out_     PHKEY phkResult
)
{
	return reg.ConnectRegistryA(lpMachineName, hKey, phkResult);
}

extern "C" LONG WINAPI RegCreateKeyA(
  _In_      HKEY hKey,
  _In_opt_  LPCSTR lpSubKey,
  _Out_     PHKEY phkResult
)
{
	return reg.CreateKeyA(hKey, lpSubKey, phkResult);
}

extern "C" LONG WINAPI RegCreateKeyExA(
  _In_        HKEY hKey,
  _In_        LPCSTR lpSubKey,
  _Reserved_  DWORD Reserved,
  _In_opt_    LPSTR lpClass,
  _In_        DWORD dwOptions,
  _In_        REGSAM samDesired,
  _In_opt_    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _Out_       PHKEY phkResult,
  _Out_opt_   LPDWORD lpdwDisposition
)
{
	return reg.CreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, 
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

extern "C" LONG WINAPI RegOpenKeyA(
  _In_      HKEY hKey,
  _In_opt_  LPCSTR lpSubKey,
  _Out_     PHKEY phkResult
)
{
	return  reg.OpenKeyA(hKey, lpSubKey, phkResult);
}

extern "C" LONG WINAPI RegOpenKeyExA(
  _In_        HKEY hKey,
  _In_opt_    LPCSTR lpSubKey,
  _Reserved_  DWORD ulOptions,
  _In_        REGSAM samDesired,
  _Out_       PHKEY phkResult
)
{
	return  reg.OpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

extern "C" LONG WINAPI RegQueryValueA(
  _In_         HKEY hKey,
  _In_opt_     LPCSTR lpSubKey,
  _Out_opt_    LPSTR lpValue,
  _Inout_opt_  PLONG lpcbValue
)
{
	return  reg.QueryValueA(hKey, lpSubKey, lpValue, lpcbValue);
}

extern "C" LONG WINAPI RegQueryValueExA(
  _In_         HKEY hKey,
  _In_opt_     LPCSTR lpValueName,
  _Reserved_   LPDWORD lpReserved,
  _Out_opt_    LPDWORD lpType,
  _Out_opt_    LPBYTE lpData,
  _Inout_opt_  LPDWORD lpcbData
)
{
	return  reg.QueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

extern "C" LONG WINAPI RegSetValueA(
  _In_      HKEY hKey,
  _In_opt_  LPCSTR lpSubKey,
  _In_      DWORD dwType,
  _In_      LPCSTR lpData,
  _In_      DWORD cbData
)
{
	return  reg.SetValueA(hKey, lpSubKey, dwType, lpData, cbData);
}


extern "C" LONG WINAPI RegSetValueExA(
  _In_        HKEY hKey,
  _In_opt_    LPCSTR lpValueName,
  _Reserved_  DWORD Reserved,
  _In_        DWORD dwType,
  _In_        const BYTE *lpData,
  _In_        DWORD cbData
)
{
	return  reg.SetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}
