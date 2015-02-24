/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include <Windows.h>
#include <Shlwapi.h>
#include <iostream>
#include <fstream>
#include <vector>

#include "Advapi_Stuff.h"

enum
{
	MODE_AUTO,
	MODE_PATCH,
	MODE_UNPATCH
};

int setting_mode = MODE_AUTO;

static void find_all(char *buffer, char *str, size_t sizebuf, size_t size_str, std::vector<size_t> &pos)
{
	sizebuf -= size_str;

	for (size_t i = 0; i < sizebuf; i++)
	{
		if (!_strnicmp(&buffer[i], str, size_str))
			pos.push_back(i);
	}
}

static size_t find_single(char *buffer, char *str, size_t sizebuf, size_t size_str)
{
	sizebuf -= size_str;
	size_t pos = 0;

	for (size_t i = 0; i < sizebuf; i++)
	{
		if (!strncmp(&buffer[i], str, size_str))
		{
			pos = i;
			break;
		}
	}

	return pos;
}

static void CheapWide(char *str, wchar_t *out, size_t length)
{
	char *cbuf = (char*)out;

	memset(cbuf, 0, length * 2);
	
	size_t str_len = strlen(str);

	for(size_t i = 0; i < str_len; i++)
		cbuf[i*2] = str[i];
}

std::wstring parse_command_line(int count, wchar_t* lines[])
{
	std::vector<std::wstring> vlines;
	std::wstring out;

	while (count--)
	{
		if (StrStrIW(lines[count], L"regemu32") == nullptr)
			vlines.push_back(std::wstring(lines[count]));
	}

	for (std::wstring &ws : vlines)
	{
		if (!_wcsicmp(ws.c_str(), L"-u") || !_wcsicmp(ws.c_str(), L"--unpatch"))
			setting_mode = MODE_UNPATCH;

		else if (!_wcsicmp(ws.c_str(), L"-p") || !_wcsicmp(ws.c_str(), L"--patch"))
			setting_mode = MODE_PATCH;
		else
			out = ws;
	}

	return out;
}

bool patch(std::fstream &file, char* buffer, size_t size)
{
	std::vector<size_t> advapi;
	find_all(buffer, "ADVAPI32", size, 8, advapi);

	std::vector<int> functionlist;

	bool fullcheck = false;
	bool supported = true;

	if (!advapi.empty())
	{
		if (fullcheck) for (int i = 0; i < 806; i++)
		{
			size_t func_len = strlen(Advapi_Function[i]);

			if (find_single(buffer, Advapi_Function[i], size, func_len))
			{
				functionlist.push_back(i);
				supported = supported && Advapi_Support[i];
			}
		};

		if (supported)
		{
			for (size_t pos : advapi)
			{
				file.seekg(pos, std::ios::beg);
				file.write("REGEMU32", 8);
			}
		}

		wprintf(L"ADVAPI32 found (%d) and patched. ", advapi.size());
	}
	else
	{
		wprintf(L"ADVAPI32 not found. ");
	}

	return !advapi.empty();
}

bool unpatch(std::fstream &file, char* buffer, size_t size)
{
	std::vector<size_t> regemu;
	find_all(buffer, "REGEMU32", size, 8, regemu);

	if (!regemu.empty())
	{
		for (size_t pos : regemu)
		{
			file.seekg(pos, std::ios::beg);
			file.write("ADVAPI32", 8);
		}

		wprintf(L"REGEMU32 found (%d) and unpatched. ", regemu.size());
	}
	else
	{
		wprintf(L"REGEMU32 not found. ");
	}

	return !regemu.empty();
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		wprintf(L"Regemu Patcher\n\n");
		wprintf(L"Usage: REGEMU32 file [option]\n\n");
		wprintf(L"  -p,  --patch             Replaces ADVAPI32 with REGEMU32 in FILE.\n");
		wprintf(L"  -u,  --unpatch           Replaces REGEMU32 with ADVAPI32 in FILE.\n");
		wprintf(L"\nDefault auto mode, unpatch is run if patch is unsuccessful.\n");

		return ERROR_SUCCESS;
	}

	std::wstring filename = parse_command_line(argc, argv);
	if (filename.empty()) return ERROR_SUCCESS;

	if (filename[0] == L'"') filename = filename.substr(1, filename.find_last_of(L'"') - 1);
	wprintf(L"%s (%d): ", filename.c_str(), setting_mode);

	std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary | std::ios::ate);
	
	if(file.is_open())
	{
		size_t size = static_cast<size_t>(file.tellg());
		char *buffer = new char[size];

		file.seekg(0, std::ios::beg);
		file.read(buffer, size);

		switch (setting_mode)
		{
		case MODE_AUTO: if (!patch(file, buffer, size)) unpatch(file, buffer, size); break;
		case MODE_PATCH: patch(file, buffer, size);  break;
		case MODE_UNPATCH: unpatch(file, buffer, size);  break;
		}

		wprintf(L"\n");

		//for each(int func in functionlist)
		//{
		//	wchar_t buff[64]; 
		//	CheapWide(Advapi_Function[func], buff, 64);
		//	message.append(buff).append(Advapi_Support[func] ? L"\t[o]" : L"\t[x]").append(L"\n");
		//}

		delete[] buffer;
		file.close();
	}
	else
	{
		wprintf(L"Could not open file.\n");
	}
	
	return EXIT_SUCCESS;
}
