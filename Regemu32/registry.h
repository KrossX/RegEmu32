/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#pragma once

#include <vector>

struct reg_value
{
	std::wstring name, data;

	DWORD type = 1;

	bool operator < (const reg_value& val) const
	{
		return (_wcsicmp(name.c_str(), val.name.c_str()) < 0);
	}
};

struct reg_key
{
	std::wstring name;
	std::vector<reg_key> child;
	std::vector<reg_value> value;
	
	reg_value def;

	bool operator < (const reg_key& key) const
	{
		return (_wcsicmp(name.c_str(), key.name.c_str()) < 0);
	}
};

struct reg_handle
{
	bool open = false;
	reg_key *key;
};


struct windows_registry
{
	std::vector<reg_key> key;
	std::vector<reg_key*> handle;

	int handle_size;

	windows_registry();
	~windows_registry();

	int new_handle(reg_key *key)
	{
		handle.push_back(key);
		handle_size++;
		return handle_size-1;
	}

private:
	windows_registry(const windows_registry& other); // copy
	windows_registry(windows_registry&& other); // move

	windows_registry& operator= (const windows_registry& other);
	windows_registry& operator= (windows_registry&& other);
};