#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>

#include "Advapi_Stuff.h"

wchar_t *Patcher_Message[] = 
{
	L"ADVAPI not found.",
	L"ADVAPI found, but unsupported. =(",
	L"ADVAPI found and patched! =]",
	L"REGEMU found, uninstalled."
};

enum
{
	MSG_NOT_FOUND = 0,
	MSG_FOUND_UNSUPPORTED,
	MSG_FOUND_PATCHED,
	MSG_UNINSTALLED
};


static size_t FindString(char *buffer, char *str, size_t sizebuf, size_t size_str)
{
	sizebuf -= size_str;
	size_t pos = 0;
	
	for(size_t i = 0; i < sizebuf; i++)
	{
		if(!strncmp(&buffer[i], str, size_str))
		{
			pos = i;
			break;
		}
	}

	return pos;
}

static void CheapWide(char *str, wchar_t *out, size_t length)
{
	memset(out, 0, length);
	
	char *cbuf = (char*)out;

	size_t str_len = strlen(str);

	for(size_t i = 0; i < str_len; i++)
		cbuf[i*2] = str[i];
}

int CALLBACK wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
	using namespace std;
	
	vector<int> functionlist;
	
	wchar_t message[2048];
	int msg = 0;

	wstring filename(lpCmdLine);
	if(filename[0] == L'"') filename = filename.substr(1, filename.find_last_of(L'"') - 1);

	fstream file(filename, ios::in | ios::out | ios::binary | ios::ate);

	if(file.is_open())
	{
		size_t size = static_cast<size_t>(file.tellg());
		char *buffer = new char[size];

		file.seekg(0, ios::beg);
		file.read(buffer, size);

		size_t advapi_pos = FindString(buffer, "ADVAPI32", size, 8);

		bool supported = true;

		if(advapi_pos)
		{
			for(int i = 0; i < 806; i++)
			{
				size_t func_len = strlen(Advapi_Function[i]);

				if(FindString(buffer, Advapi_Function[i], size, func_len))
				{
					functionlist.push_back(i);
					supported = supported && Advapi_Support[i];
				}
			};

			if(supported)
			{
				file.seekg(advapi_pos, ios::beg);
				file.write("REGEMU32", 8);
			}

			msg = supported? MSG_FOUND_PATCHED : MSG_FOUND_UNSUPPORTED;
		}
		else
		{
			size_t regemu_pos = FindString(buffer, "REGEMU32", size, 8);

			if(regemu_pos)
			{
				file.seekg(regemu_pos, ios::beg);
				file.write("ADVAPI32", 8);
				msg = MSG_UNINSTALLED;
			}
		}

		swprintf_s(message, L"%s\n", Patcher_Message[msg]);

		for each(int func in functionlist)
		{
			wchar_t buff[128]; 
			CheapWide(Advapi_Function[func], buff, 128);
			swprintf_s(message, L"%s\n%s \t[%s]", message, buff, Advapi_Support[func] ? L"o" : L"x");
		}

		delete[] buffer;
		file.close();
	}
	else
	{
		swprintf_s(message, L"Could not open file:\n%s", filename.c_str());
	}
	
	MessageBoxW(NULL, message, L"Command line", MB_OK);

	return EXIT_SUCCESS;
}
