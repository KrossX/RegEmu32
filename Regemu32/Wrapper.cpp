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
	return regemu::create_key(hKey, NULL, phkResult, nullptr, true);
}

LSTATUS WINAPI reg_connect_registry_ex_a(LPCSTR lpMachineName, HKEY hKey, ULONG Flags, PHKEY phkResult)
{
	//return RegConnectRegistryExA(lpMachineName, hKey, Flags, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, nullptr, true);
}

LSTATUS WINAPI reg_connect_registry_ex_w(LPCWSTR lpMachineName, HKEY hKey, ULONG Flags, PHKEY phkResult)
{
	//return RegConnectRegistryExW(lpMachineName, hKey, Flags, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, nullptr, true);
}

LSTATUS WINAPI reg_connect_registry_w(LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult)
{
	//return RegConnectRegistryW(lpMachineName, hKey, phkResult);
	return regemu::create_key(hKey, NULL, phkResult, nullptr, true);
}

LSTATUS WINAPI reg_create_key_a(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	//return RegCreateKeyA(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, nullptr, false);
}

LSTATUS WINAPI reg_create_key_ex_a(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	//return RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, lpdwDisposition, false);
}

LSTATUS WINAPI reg_create_key_ex_w(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	//return RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	return regemu::create_key(hKey, lpSubKey, phkResult, lpdwDisposition, false);
}

LSTATUS WINAPI reg_create_key_w(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
	//return RegCreateKeyW(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, nullptr, false);
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

LSTATUS WINAPI reg_get_value_a(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
	//return RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
	return regemu::query_value_ex(hKey, atow(lpSubKey), atow(lpValue), pdwType, (LPBYTE)pvData, pcbData, false);
}

LSTATUS WINAPI reg_get_value_w(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
	//return RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
	return regemu::query_value_ex(hKey, lpSubKey, lpValue, pdwType, (LPBYTE)pvData, pcbData, true);
}

LSTATUS WINAPI reg_open_key_a(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	//return RegOpenKeyA(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, nullptr, true);
}

LSTATUS WINAPI reg_open_key_ex_a(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	//return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return regemu::create_key(hKey, atow(lpSubKey), phkResult, nullptr, true);
}

LSTATUS WINAPI reg_open_key_ex_w(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	//return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, nullptr, true);
}

LSTATUS WINAPI reg_open_key_w(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
	//return RegOpenKeyW(hKey, lpSubKey, phkResult);
	return regemu::create_key(hKey, lpSubKey, phkResult, nullptr, true);
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

BOOL WINAPI access_check(PSECURITY_DESCRIPTOR a, HANDLE b, DWORD c, PGENERIC_MAPPING d, PPRIVILEGE_SET e, LPDWORD f, LPDWORD g, LPBOOL h)
{ return AccessCheck(a, b, c, d, e, f, g, h); }

BOOL WINAPI add_access_allowed_ace(PACL a, DWORD b, DWORD c, PSID d)
{ return AddAccessAllowedAce(a, b, c, d); }

BOOL WINAPI adjust_token_privileges(HANDLE a, BOOL b, PTOKEN_PRIVILEGES c, DWORD d, PTOKEN_PRIVILEGES e, PDWORD f)
{ return AdjustTokenPrivileges(a, b, c, d, e, f); }

BOOL WINAPI allocate_and_initialize_sid(PSID_IDENTIFIER_AUTHORITY a, BYTE b, DWORD c, DWORD d, DWORD e, DWORD f, DWORD g, DWORD h, DWORD i, DWORD j, PSID *k)
{ return AllocateAndInitializeSid(a, b, c, d, e, f, g, h, i, j, k); }

BOOL WINAPI check_token_membership(HANDLE a, PSID b, PBOOL c)
{ return CheckTokenMembership(a, b, c); }

BOOL WINAPI crypt_acquire_context_a(HCRYPTPROV *a, LPCSTR b, LPCSTR c, DWORD d, DWORD e)
{ return CryptAcquireContextA(a, b, c, d, e); }

BOOL WINAPI crypt_acquire_context_w(HCRYPTPROV *a, LPCWSTR b, LPCWSTR c, DWORD d, DWORD e)
{ return CryptAcquireContextW(a, b, c, d, e); }

BOOL WINAPI crypt_context_add_ref(HCRYPTPROV a, DWORD *b, DWORD c)
{ return CryptContextAddRef(a, b, c); }

BOOL WINAPI crypt_create_hash(HCRYPTPROV a, ALG_ID b, HCRYPTKEY c, DWORD d, HCRYPTHASH *e)
{ return CryptCreateHash(a, b, c, d ,e); }

BOOL WINAPI crypt_decrypt(HCRYPTKEY a, HCRYPTHASH b, BOOL c, DWORD d, BYTE *e, DWORD *f)
{ return CryptDecrypt(a, b, c, d, e, f); }

BOOL WINAPI crypt_derive_key(HCRYPTPROV a, ALG_ID b, HCRYPTKEY c, DWORD d, HCRYPTHASH *e)
{ return CryptDeriveKey(a, b, c, d, e); }

BOOL WINAPI crypt_destroy_hash(HCRYPTHASH a)
{ return CryptDestroyHash(a); }

BOOL WINAPI crypt_destroy_key(HCRYPTKEY a)
{ return CryptDestroyKey(a); }

BOOL WINAPI crypt_duplicate_hash(HCRYPTHASH a, DWORD *b, DWORD c, HCRYPTHASH *d)
{ return CryptDuplicateHash(a, b, c, d); }

BOOL WINAPI crypt_duplicate_key(HCRYPTKEY a, DWORD *b, DWORD c, HCRYPTKEY *d)
{ return CryptDuplicateKey(a, b, c, d); }

BOOL WINAPI crypt_encrypt(HCRYPTKEY a, HCRYPTHASH b, BOOL c, DWORD d, BYTE *e, DWORD *f, DWORD g)
{ return CryptEncrypt(a, b, c, d, e, f, g); }

BOOL WINAPI crypt_enum_provider_types_a(DWORD a, DWORD *b, DWORD c, DWORD *d, LPSTR e, DWORD *f)
{ return CryptEnumProviderTypesA(a, b, c, d, e, f); }

BOOL WINAPI crypt_enum_provider_types_w(DWORD a, DWORD *b, DWORD c, DWORD *d, LPWSTR e, DWORD *f)
{ return CryptEnumProviderTypesW(a, b, c, d, e, f); }

BOOL WINAPI crypt_enum_providers_a(DWORD a, DWORD *b, DWORD c, DWORD *d, LPSTR e, DWORD *f)
{ return CryptEnumProvidersA(a, b, c, d, e, f); }

BOOL WINAPI crypt_enum_providers_w(DWORD a, DWORD *b, DWORD c, DWORD *d, LPWSTR e, DWORD *f)
{ return CryptEnumProvidersW(a, b, c, d, e, f); }

BOOL WINAPI crypt_export_key(HCRYPTKEY a, HCRYPTKEY b, DWORD c, DWORD d, BYTE *e, DWORD *f)
{ return CryptExportKey(a, b, c, d, e, f); }

BOOL WINAPI crypt_gen_key(HCRYPTPROV a, ALG_ID b, DWORD c, HCRYPTKEY *d)
{ return CryptGenKey(a, b, c, d); }

BOOL WINAPI crypt_gen_random(HCRYPTPROV a, DWORD b, BYTE *c)
{ return CryptGenRandom(a, b, c); }

BOOL WINAPI crypt_get_default_provider_a(DWORD a, DWORD *b, DWORD c, LPSTR d, DWORD *e)
{ return CryptGetDefaultProviderA(a, b, c, d, e); }

BOOL WINAPI crypt_get_default_provider_w(DWORD a, DWORD *b, DWORD c, LPWSTR d, DWORD *e)
{ return CryptGetDefaultProviderW(a, b, c, d, e); }

BOOL WINAPI crypt_get_hash_param(HCRYPTHASH a, DWORD b, BYTE *c, DWORD *d, DWORD e)
{ return CryptGetHashParam(a, b, c, d, e); }

BOOL WINAPI crypt_get_key_param(HCRYPTHASH a, DWORD b, BYTE *c, DWORD *d, DWORD e)
{ return CryptGetKeyParam(a, b, c, d, e); }

BOOL WINAPI crypt_get_prov_param(HCRYPTPROV a, DWORD b, BYTE *c, DWORD *d, DWORD e)
{ return CryptGetProvParam(a, b, c, d, e); }

BOOL WINAPI crypt_get_user_key(HCRYPTPROV a, DWORD b, HCRYPTKEY *c)
{ return CryptGetUserKey(a, b, c); }

BOOL WINAPI crypt_hash_data(HCRYPTHASH a, const BYTE* b, DWORD c, DWORD d)
{ return CryptHashData(a, b, c, d); }

BOOL WINAPI crypt_hash_session_key(HCRYPTHASH a, HCRYPTKEY b, DWORD c)
{ return CryptHashSessionKey(a, b, c); }

BOOL WINAPI crypt_import_key(HCRYPTHASH a, const BYTE* b, DWORD c, HCRYPTKEY d, DWORD e, HCRYPTKEY *f)
{ return CryptImportKey(a, b, c, d, e, f); }

BOOL WINAPI crypt_release_context(HCRYPTPROV a, DWORD b)
{ return CryptReleaseContext(a, b); }

BOOL WINAPI crypt_set_hash_param(HCRYPTHASH a, DWORD b, const BYTE* c, DWORD d)
{ return CryptSetHashParam(a, b, c, d); }

BOOL WINAPI crypt_set_key_param(HCRYPTKEY a, DWORD b, const BYTE* c, DWORD d)
{ return CryptSetKeyParam(a, b, c, d); }

BOOL WINAPI crypt_set_prov_param(HCRYPTPROV a, DWORD b, const BYTE* c, DWORD d)
{ return CryptSetProvParam(a, b, c, d); }

BOOL WINAPI crypt_set_provider_a(LPCSTR a, DWORD b)
{ return CryptSetProviderA(a, b); }

BOOL WINAPI crypt_set_provider_ex_a(LPCSTR a, DWORD b, DWORD *c, DWORD d)
{ return CryptSetProviderExA(a, b, c, d); }

BOOL WINAPI crypt_set_provider_ex_w(LPCWSTR a, DWORD b, DWORD *c, DWORD d)
{ return CryptSetProviderExW(a, b, c, d); }

BOOL WINAPI crypt_set_provider_w(LPCWSTR a, DWORD b)
{ return CryptSetProviderW(a, b); }

BOOL WINAPI crypt_sign_hash_a(HCRYPTHASH a, DWORD b, LPCSTR c, DWORD d, BYTE *e, DWORD *f)
{ return CryptSignHashA(a, b, c, d, e ,f); }

BOOL WINAPI crypt_sign_hash_w(HCRYPTHASH a, DWORD b, LPCWSTR c, DWORD d, BYTE *e, DWORD *f)
{ return CryptSignHashW(a, b, c, d, e ,f); }

BOOL WINAPI crypt_verify_signature_a(HCRYPTHASH a, const BYTE *b, DWORD c, HCRYPTKEY d, LPCSTR e, DWORD f)
{ return CryptVerifySignatureA(a, b, c, d, e ,f); }

BOOL WINAPI crypt_verify_signature_w(HCRYPTHASH a, const BYTE *b, DWORD c, HCRYPTKEY d, LPCWSTR e, DWORD f)
{ return CryptVerifySignatureW(a, b, c, d, e ,f); }

BOOL WINAPI duplicate_token(HANDLE a, SECURITY_IMPERSONATION_LEVEL b, PHANDLE c)
{ return DuplicateToken(a, b, c); }

BOOL WINAPI equal_sid(PSID a, PSID b)
{ return EqualSid(a, b); }

PVOID WINAPI free_sid(PSID a)
{ return FreeSid(a); }

DWORD WINAPI get_length_sid(PSID a)
{ return GetLengthSid(a); }

BOOL WINAPI get_token_information(HANDLE a, TOKEN_INFORMATION_CLASS b, LPVOID c, DWORD d, PDWORD e)
{ return GetTokenInformation(a, b, c, d, e); }

BOOL WINAPI get_user_name_a(LPSTR lpBuffer, LPDWORD pcbBuffer)
{ return GetUserNameA(lpBuffer, pcbBuffer); }

BOOL WINAPI get_user_name_w(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{ return GetUserNameW(lpBuffer, pcbBuffer); }

BOOL WINAPI initialize_acl(PACL a, DWORD b, DWORD c)
{ return InitializeAcl(a, b, c); }

BOOL WINAPI initialize_security_descriptor(PSECURITY_DESCRIPTOR a, DWORD b)
{ return InitializeSecurityDescriptor(a, b); }

BOOL WINAPI is_valid_security_descriptor(PSECURITY_DESCRIPTOR a)
{ return IsValidSecurityDescriptor(a); }

BOOL WINAPI lookup_privilege_value_w(LPCWSTR a, LPCWSTR b, PLUID c)
{ return LookupPrivilegeValueW(a, b, c); }

BOOL WINAPI open_process_token(HANDLE a, DWORD b, PHANDLE c)
{ return OpenProcessToken(a, b, c); }

BOOL WINAPI open_thread_token(HANDLE a, DWORD b, BOOL c, PHANDLE d)
{ return OpenThreadToken(a, b, c, d); }

BOOL WINAPI set_security_descriptor_dacl(PSECURITY_DESCRIPTOR a, BOOL b, PACL c, BOOL d)
{ return SetSecurityDescriptorDacl(a, b, c, d); }

BOOL WINAPI set_security_descriptor_group(PSECURITY_DESCRIPTOR a, PSID b, BOOL c)
{ return SetSecurityDescriptorGroup(a, b, c); }

BOOL WINAPI set_security_descriptor_owner(PSECURITY_DESCRIPTOR a, PSID b, BOOL c)
{ return SetSecurityDescriptorOwner(a, b, c); }