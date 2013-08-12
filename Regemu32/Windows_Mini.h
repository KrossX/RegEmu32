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

struct HKEY__
{
	int unused;
};

typedef unsigned char BYTE;
typedef char CHAR;
typedef int BOOL;
typedef long LONG;
typedef int *HINSTANCE;
typedef HKEY__ *HKEY;
typedef HKEY *PHKEY;
typedef unsigned long DWORD;
typedef DWORD *LPDWORD;
typedef LONG *PLONG;
typedef BYTE *LPBYTE;
typedef void *LPVOID;
typedef const char *LPCSTR;
typedef CHAR *LPSTR;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK REGSAM;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

#define NULL 0
#define TRUE 1
#define UNREFERENCED_PARAMETER(P) (P)

#define WINAPI __stdcall
#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1

#define _SAL_nop_impl_ X
#define _SA_annotes3(n,pp1,pp2,pp3)
#define _Group_impl_(annos)
#define _Group_(annos) _Group_impl_(annos _SAL_nop_impl_)

#define _SAL1_1_Source_(Name, args, annotes) _SA_annotes3(SAL_name, #Name, "", "1.1") _Group_(annotes _SAL_nop_impl_)
#define _SAL2_Source_(Name, args, annotes) _SA_annotes3(SAL_name, #Name, "", "2") _Group_(annotes _SAL_nop_impl_)

#define _Pre1_impl_(p1)
#define _Pre_valid_impl_
#define _Deref_pre1_impl_(p1)
#define _Post_valid_impl_
#define _Pre_valid_                     _SAL2_Source_(_Pre_valid_, (), _Pre1_impl_(__notnull_impl_notref)   _Pre_valid_impl_)
#define _Pre_opt_valid_                 _SAL2_Source_(_Pre_opt_valid_, (), _Pre1_impl_(__maybenull_impl_notref) _Pre_valid_impl_)
#define _Post_valid_                    _SAL2_Source_(_Post_valid_, (), _Post_valid_impl_)
#define _Deref_pre_readonly_            _SAL1_1_Source_(_Deref_pre_readonly_, (), _Deref_pre1_impl_(__readaccess_impl_notref))
#define _Prepost_valid_                 _SAL1_1_Source_(_Prepost_valid_, (), _Pre_valid_     _Post_valid_)
#define _Prepost_opt_valid_             _SAL1_1_Source_(_Prepost_opt_valid_, (), _Pre_opt_valid_ _Post_valid_)

#define _In_                            _SAL2_Source_(_In_, (), _Pre1_impl_(__notnull_impl_notref) _Pre_valid_impl_ _Deref_pre1_impl_(__readaccess_impl_notref))
#define _In_opt_                        _SAL2_Source_(_In_opt_, (), _Pre1_impl_(__maybenull_impl_notref) _Pre_valid_impl_ _Deref_pre_readonly_)
#define _Reserved_                      _SAL2_Source_(_Reserved_, (), _Pre1_impl_(__null_impl))
#define _Out_                           _SAL2_Source_(_Out_, (),     _Out_impl_)
#define _Out_opt_                       _SAL2_Source_(_Out_opt_, (), _Out_opt_impl_)
#define _Inout_                         _SAL2_Source_(_Inout_, (), _Prepost_valid_)
#define _Inout_opt_                     _SAL2_Source_(_Inout_opt_, (), _Prepost_opt_valid_)