/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include "regemu.h"
#include "registry.h"

#include <fstream>
#include <algorithm>
#include <sstream>

const wchar_t ini_filename[] = L"./Regemu32.INI";

const wchar_t *key_string[] =
{
	L"HKEY_CLASSES_ROOT",
	L"HKEY_CURRENT_USER",
	L"HKEY_LOCAL_MACHINE",
	L"HKEY_USERS",
	L"HKEY_PERFORMANCE_DATA",
	L"HKEY_CURRENT_CONFIG",
	L"HKEY_DYN_DATA",
	L"HKEY_CURRENT_USER_LOCAL_SETTINGS",
	L"HKEY_PERFORMANCE_TEXT",
	L"HKEY_PERFORMANCE_NLSTEXT",
};

HKEY get_predefined_key(std::wstring key)
{
	if (std::wcscmp(key_string[0], key.c_str()) == 0) return HKEY_CLASSES_ROOT;
	if (std::wcscmp(key_string[1], key.c_str()) == 0) return HKEY_CURRENT_USER;
	if (std::wcscmp(key_string[2], key.c_str()) == 0) return HKEY_LOCAL_MACHINE;
	if (std::wcscmp(key_string[3], key.c_str()) == 0) return HKEY_USERS;
	if (std::wcscmp(key_string[4], key.c_str()) == 0) return HKEY_PERFORMANCE_DATA;
	if (std::wcscmp(key_string[5], key.c_str()) == 0) return HKEY_CURRENT_CONFIG;
	if (std::wcscmp(key_string[6], key.c_str()) == 0) return HKEY_DYN_DATA;
	if (std::wcscmp(key_string[7], key.c_str()) == 0) return HKEY_CURRENT_USER_LOCAL_SETTINGS;
	if (std::wcscmp(key_string[8], key.c_str()) == 0) return HKEY_PERFORMANCE_TEXT;
	if (std::wcscmp(key_string[9], key.c_str()) == 0) return HKEY_PERFORMANCE_NLSTEXT;
	return (HKEY)-1;
}

windows_registry::windows_registry()
{
	key.clear();
	handle.clear();
	handle_size = 0;

	for (int i = 0; i < 10; i++)
	{
		reg_key new_key;
		new_key.name = key_string[i];
		key.push_back(new_key);
	}

	std::wifstream infile(ini_filename);

	if (infile.is_open())
	{
		HKEY curr_hkey = (HKEY)-1;
		std::wstring line, valuename;

		while (!infile.eof())
		{
			std::getline(infile, line);

			if (line[0] == L'[') // Key
			{
				line = line.substr(1, line.length() - 2);
				auto slash = line.find(L'\\');

				curr_hkey = get_predefined_key(line.substr(0, slash));
				regemu::create_key(curr_hkey, line.substr(slash + 1).c_str(), &curr_hkey, false);
			}
			else if (line[0] == L'@' || line[0] == L'\"')
			{
				valuename = line[0] == L'@' ? L"" : line.substr(1, line.find('=') - 2);
				line = line.substr(line.find('=') + 1);

				if (line[0] == '\"')
				{
					line = line.substr(1, line.length() - 2);
					regemu::set_value_ex(curr_hkey, nullptr, valuename.c_str(), REG_SZ, (BYTE*)line.c_str(), line.size() * sizeof(wchar_t), true);
				}
				else
				{
					if (std::wcsncmp(line.c_str(), L"dwor", 4) == 0)
					{
						DWORD number = std::wcstoul(line.substr(6).c_str(), nullptr, 16);
						regemu::set_value_ex(curr_hkey, nullptr, valuename.c_str(), REG_DWORD, (BYTE*)&number, sizeof(DWORD), true);
					}
					else if (std::wcsncmp(line.c_str(), L"hex:", 4) == 0 || std::wcsncmp(line.c_str(), L"hex(", 4) == 0)
					{
						DWORD type = line[3] == L':' ? REG_BINARY : std::wcstoul(&line[4], nullptr, 16);
						size_t bytes = std::count(line.begin(), line.end(), L',') + 1;
						BYTE *buffer = new BYTE[bytes + 2];
						memset(buffer, 0, bytes + 2);

						wchar_t *point = &line[line.find(L':') + 1];

						for (size_t i = 0; i < bytes; i++)
						{
							buffer[i] = std::wcstoul(point, &point, 16) & 0xFF;
							point++;
						}
						

						regemu::set_value_ex(curr_hkey, nullptr, valuename.c_str(), type, buffer, bytes, true);
						delete[] buffer;
					}
				}
			}
		}



		infile.close();
	}

	// open file and load values
}

std::wstring outdata(reg_value &value)
{
	std::wstringstream stream;

	if (value.type == 1)
	{
		stream << L"\"" << value.data << L"\"";
	}
	else
	{
		if (value.type == 3)
			stream << L"hex:";
		else if (value.type == 4)
			stream << L"dword:";
		else
			stream << L"hex(" << std::hex << value.type << L"):";

		stream << value.data;
	}

	return stream.str();
}

void outvalues(reg_key *curr_key, std::wstring str, std::wofstream &out)
{
	if (!curr_key->value.empty() || !curr_key->def.data.empty())
	{
		std::sort(curr_key->value.begin(), curr_key->value.end());

		out << str << curr_key->name << L"]\n";

		if (!curr_key->def.data.empty())
			out << L"@=" << outdata(curr_key->def) << L"\n";
		
		for (reg_value &val : curr_key->value)
			out << L"\"" << val.name << L"\"=" << outdata(val) << L"\n";

		out << L"\n";
	}

	str.append(curr_key->name).append(L"\\");

	std::sort(curr_key->child.begin(), curr_key->child.end());

	for (reg_key &curr : curr_key->child)
		outvalues(&curr, str, out);
}

windows_registry::~windows_registry()
{
	std::wofstream outfile(ini_filename);

	if (outfile.is_open())
	{
		for (reg_key &k : key)
		{
			std::sort(k.child.begin(), k.child.end());

			std::wstring str(L"[");
			outvalues(&k, str, outfile);
		}

		outfile.close();
	}



	// sort and save to disk
	// do not save empty entries?
}

//const std::string& get_key_string(HKEY key)
//{
//	switch ((DWORD)key)
//	{
//	case 0x80000000: return key_string[0x00];
//	case 0x80000001: return key_string[0x01];
//	case 0x80000002: return key_string[0x02];
//	case 0x80000003: return key_string[0x03];
//	case 0x80000004: return key_string[0x04];
//	case 0x80000005: return key_string[0x05];
//	case 0x80000006: return key_string[0x06];
//	case 0x80000007: return key_string[0x07];
//	case 0x80000050: return key_string[0x08];
//	case 0x80000060: return key_string[0x09];
//	default:		 return key_string[0x0A];
//	}
//}
//
//const std::string get_type_string(DWORD type)
//{
//	switch (type)
//	{
//	case 0x00:	return type_string[0x00];
//	case 0x01:	return type_string[0x01];
//	case 0x02:	return type_string[0x02];
//	case 0x03:	return type_string[0x03];
//	case 0x04:	return type_string[0x04];
//	case 0x05:	return type_string[0x05];
//	case 0x06:	return type_string[0x06];
//	case 0x07:	return type_string[0x07];
//	case 0x08:	return type_string[0x08];
//	case 0x09:	return type_string[0x09];
//	case 0x0A:	return type_string[0x0A];
//	case 0x0B:	return type_string[0x0B];
//	default:	return type_string[0x0C];
//	}
//}