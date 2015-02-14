/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>

#include "Advapi_Stuff.h"


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

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		wprintf(L"Regemu Patcher usage:\n\n");
		wprintf(L"\tREGEMU32 file\n\n");
		wprintf(L"Replaces \"ADVAPI32\" with \"REGEMU32\" in FILE, and vice-versa.\n");
		return ERROR_SUCCESS;
	}
	
	bool fullcheck = false;
	std::vector<int> functionlist;

	
	std::wstring filename(argv[1]);
	if(filename[0] == L'"') filename = filename.substr(1, filename.find_last_of(L'"') - 1);

	std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary | std::ios::ate);

	if(file.is_open())
	{
		wprintf(L"%s: ", filename.c_str());

		size_t size = static_cast<size_t>(file.tellg());
		char *buffer = new char[size];

		file.seekg(0, std::ios::beg);
		file.read(buffer, size);

		std::vector<size_t> advapi;
		find_all(buffer, "ADVAPI32", size, 8, advapi);

		bool supported = true;

		if (!advapi.empty())
		{
			if (fullcheck) for(int i = 0; i < 806; i++)
			{
				size_t func_len = strlen(Advapi_Function[i]);

				if(find_single(buffer, Advapi_Function[i], size, func_len))
				{
					functionlist.push_back(i);
					supported = supported && Advapi_Support[i];
				}
			};

			if(supported)
			{
				for (size_t pos : advapi)
				{
					file.seekg(pos, std::ios::beg);
					file.write("REGEMU32", 8);
				}
			}

			wprintf(L"ADVAPI32 found (%d) and patched.\n", advapi.size());
		}
		else
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

				wprintf(L"REGEMU32 found (%d) and unpatched.\n", regemu.size());
			}
			else
			{
				wprintf(L"Nothing found on file.\n");
			}
		}

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
