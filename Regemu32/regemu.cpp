/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include "regemu.h"
#include "registry.h"

#include <algorithm>
#include <sstream>

windows_registry registry;

reg_key* predefined_key(HKEY key)
{
	switch ((DWORD)key)
	{
	case 0x80000000: return &registry.key[0];
	case 0x80000001: return &registry.key[1];
	case 0x80000002: return &registry.key[2];
	case 0x80000003: return &registry.key[3];
	case 0x80000004: return &registry.key[4];
	case 0x80000005: return &registry.key[5];
	case 0x80000006: return &registry.key[6];
	case 0x80000007: return &registry.key[7];
	case 0x80000050: return &registry.key[8];
	case 0x80000060: return &registry.key[9];
	default:		 return nullptr;
	}
}

std::wstring tolow(std::wstring &in)
{
	std::wstring out(in.size(), 0);
	std::transform(in.begin(), in.end(), out.begin(), towlower);
	return out;
}

std::wstring get_substring(std::wstring &subkey)
{
	std::wstring newstring;

	do
	{
		auto index = subkey.find(L'\\');

		if (index != std::wstring::npos)
		{
			newstring = subkey.substr(0, index);
			subkey = subkey.substr(index + 1);
		}
		else
		{
			newstring = subkey;
			subkey.clear();
		}

	} while (newstring.empty());

	return newstring;
}

reg_key* create_regkey(std::wstring &subkey, reg_key *curr_key, bool *created_new = nullptr)
{
	reg_key *k = nullptr;

	std::wstring newsubkey = get_substring(subkey);
	std::wstring subkeylow = tolow(newsubkey);

	bool found = false;
	if (created_new) *created_new = false;

	for (reg_key &child : curr_key->child)
	{
		std::wstring childlow = tolow(child.name);

		if (childlow == subkeylow)
		{
			found = true;
			k = subkey.empty() ? &child : create_regkey(subkey, &child);
		}
	}

	if (!found)
	{
		if (created_new) *created_new = true;
		reg_key newkey;
		newkey.name = newsubkey;
		curr_key->child.push_back(newkey);
		reg_key &nkp = curr_key->child.back();
		k = subkey.empty() ? &nkp : create_regkey(subkey, &nkp);
	}
	
	return k;
}

reg_key* find_key(std::wstring &subkey, reg_key *curr_key)
{
	reg_key *k = nullptr;
	
	std::wstring subkeylow = tolow(get_substring(subkey));

	for(reg_key &child : curr_key->child)
	{
		std::wstring childlow = tolow(child.name);

		if (childlow == subkeylow)
		{
			k = subkey.empty() ? &child : find_key(subkey, &child);
			break;
		}
	}

	return k;
}

reg_value* find_value(std::wstring &name, reg_key *curr_key)
{
	reg_value *v = nullptr;

	std::wstring namelow = tolow(name);

	for (reg_value &value : curr_key->value)
	{
		std::wstring vname = tolow(value.name);

		if (vname == namelow)
		{
			v = &value;
			break;
		}
	}

	return v;
}

reg_key* check_handle(HKEY hKey)
{
	reg_key *key = predefined_key(hKey);

	if (!key)
	{
		if ((int)hKey < registry.handle_size)
			key = registry.handle[(int)hKey];
	}

	return key;
}


namespace regemu
{
	LSTATUS close_key(HKEY hKey)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);

		if ((int)hKey < 0 || (int)hKey >= registry.handle_size)
			return ERROR_INVALID_HANDLE;
		else
			return ERROR_SUCCESS;
	}

	LSTATUS create_key(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult, LPDWORD lpdwDisposition, bool open)
	{
		WPRINTF(L"%s: %08X, %s\n", __FUNCTIONW__, hKey, lpSubKey);

		reg_key *curr_key = check_handle(hKey);
		if (!curr_key) return ERROR_INVALID_HANDLE;

		std::wstring subkey(lpSubKey ? lpSubKey : L"");

		if (!subkey.empty() && curr_key != nullptr)
		{
			bool created_new;

			if (open)
				curr_key = find_key(subkey, curr_key);
			else
				curr_key = create_regkey(subkey, curr_key, &created_new);

			if (lpdwDisposition) *lpdwDisposition = created_new ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;
		}
		else if (predefined_key(hKey))
		{
			*phkResult = hKey;
			return ERROR_SUCCESS;
		}

		if (curr_key != nullptr)
		{
			*phkResult = (HKEY)registry.new_handle(curr_key);
			return ERROR_SUCCESS;
		}
		else
		{
			phkResult = nullptr;
			return ERROR_FILE_NOT_FOUND;
		}

		return -1;
	}

	LSTATUS delete_key(HKEY hKey, LPCWSTR lpSubKey)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return -1;
	}

	LSTATUS delete_value(HKEY hKey, LPCWSTR lpValueName)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return -1;
	}

	LSTATUS enum_key(HKEY hKey, DWORD dwIndex, LPBYTE lpName, LPDWORD cchName, bool wide)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return -1;
	}

	LSTATUS enum_value(HKEY hKey, DWORD dwIndex, LPBYTE lpValueName, LPDWORD lpcchValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData, bool wide)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return -1;
	}

	LSTATUS flush_key(HKEY hKey)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return ERROR_SUCCESS;
	}

	LSTATUS query_info_key(HKEY hKey, LPBYTE lpClass, LPDWORD lpcchClass, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime, bool wide)
	{
		WPRINTF(L"%s\n", __FUNCTIONW__);
		return -1;
	}

	LSTATUS query_value_ex(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData, bool wide)
	{
		WPRINTF(L"%s: %08X, %s, %s, type %d, data %d, %s\n", __FUNCTIONW__, hKey, lpSubKey, lpValueName, lpType? *lpType : 0, lpcbData? *lpcbData : 0, wide ? L"wide" : L"ansi");

		std::wstring subkey(lpSubKey ? lpSubKey : L"");
		std::wstring vname(lpValueName ? lpValueName : L"");

		if (!subkey.empty() && create_key(hKey, lpSubKey, &hKey, nullptr, true) != ERROR_SUCCESS)
			return ERROR_FILE_NOT_FOUND;

		reg_key *curr_key = check_handle(hKey);
		if (!curr_key) return ERROR_INVALID_HANDLE;

		reg_value *value = nullptr;

		if (vname.empty())
		{
			value = &curr_key->def;
		}
		else
		{
			WPRINTF(L"%s: name: %s, key: %s\n", __FUNCTIONW__, vname.c_str(), curr_key->name.c_str());
			value = find_value(vname, curr_key);
			if (!value) return ERROR_FILE_NOT_FOUND;
		}

		if (lpType) *lpType = value->type;

		if(lpcbData != nullptr)
		{
			if (value->data.empty() || *lpcbData == 0) // hack...
				return ERROR_SUCCESS;

			size_t data_size = 0;

			switch (value->type)
			{
			case REG_SZ: data_size = (value->data.length() + 1) * (wide ? sizeof(wchar_t) : 1); break;
			case REG_DWORD: data_size = sizeof(DWORD);  break;
			default: data_size = std::count(value->data.begin(), value->data.end(), L',') + 1; break;
			}

			if (lpData == nullptr)
			{
				*lpcbData = data_size;
				return ERROR_SUCCESS;
			}
			else
			{
				if (data_size > *lpcbData)
					return ERROR_MORE_DATA;

				if(value->type == REG_SZ)
				{
					if (wide)
						memcpy(lpData, value->data.c_str(), data_size);
					else
						wcstombs((char*)lpData, value->data.c_str(), data_size);
				}
				else if (value->type == REG_DWORD)
				{
					DWORD number = std::wcstoul(value->data.c_str(), nullptr, 16);
					*(DWORD*)lpData = number;

					WPRINTF(L"%s: DWORD %08X, value %s\n", __FUNCTIONW__, number, value->data.c_str());
				}
				else
				{
					wchar_t *point = &value->data[0];

					for (size_t i = 0; i < data_size; i++)
					{
						lpData[i] = std::wcstoul(point, &point, 16) & 0xFF;
						point++;
					}
				}

				return ERROR_SUCCESS;
			}
		}
		else if (lpData == nullptr)
		{
			return ERROR_SUCCESS; // Query type?
		}
		else
		{
			// Copy data anyway? O.o
		}

		

		//RegQueryValueA(hKey, lpSubKey, lpValue, lpcbValue);
		//query_value_ex(hKey, atow(lpSubKey), nullptr, nullptr, (LPBYTE)lpValue, (LPDWORD)lpcbValue, false);

		//RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
		//regemu::query_value_ex(hKey, nullptr, atow(lpValueName), lpType, lpData, lpcbData, false);


		
		return -1;
	}

	LSTATUS set_value_ex(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, const BYTE *lpData, DWORD cbData, bool wide)
	{
		std::wstring subkey(lpSubKey ? lpSubKey : L"");
		std::wstring vname(lpValueName ? lpValueName : L"");

		if (!subkey.empty() && create_key(hKey, lpSubKey, &hKey, nullptr, true) != ERROR_SUCCESS)
			return ERROR_FILE_NOT_FOUND;

		reg_key *curr_key = check_handle(hKey);
		if (!curr_key) return ERROR_INVALID_HANDLE;

		reg_value *value = nullptr;

		if (vname.empty())
		{
			value = &curr_key->def;
		}
		else
		{
			value = find_value(vname, curr_key);
			
			if (!value)
			{
				reg_value new_value;
				new_value.name = vname;
				curr_key->value.push_back(new_value);
				value = &curr_key->value.back();
			}
		}

		value->type = dwType;
		value->data.clear();

		if (cbData > 0 && lpData != nullptr)
		{ 
			BYTE *buffer = new BYTE[cbData + 2];
			memset(buffer, 0, cbData + 2);
			memcpy(buffer, lpData, cbData);
			
			if (dwType == 1)
			{
				if (wide)
				{
					std::wstring data_in((wchar_t*)buffer);
					value->data = data_in;
				}
				else
				{
					std::string data_in((char*)buffer);
					std::wstring wdata(data_in.length(), 0);
					std::copy(data_in.begin(), data_in.end(), wdata.begin());
					value->data = wdata;
				}
			}
			else
			{
				if (dwType == 4)
				{
					wchar_t dwordstr[64];
					swprintf_s(dwordstr, L"%08X", *(DWORD*)buffer);
					value->data = std::wstring(dwordstr);
				}
				else
				{
					std::wstringstream stream;

					for (DWORD i = 0; i < cbData; i++)
						stream << std::hex << buffer[i] << L",";

					value->data = stream.str();
					value->data.pop_back();
				}
			}

			delete[] buffer;
		}


		WPRINTF(L"%s: %08X, %s, %s, %d, %s\n", __FUNCTIONW__, hKey, lpSubKey, lpValueName, dwType, wide ? L"wide" : L"ansi");
		return ERROR_SUCCESS;
	}


}