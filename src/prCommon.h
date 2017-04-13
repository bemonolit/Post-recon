#pragma once

/*
This file is part of Post-recon
Copyright (C) 2017 @maldevel
https://github.com/maldevel/Post-recon

Post-recon - post-exploitation reconnaissance toolkit.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more see the file 'LICENSE' for copying permission.
*/

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

namespace Common
{
	//Allocates a block of memory from a heap.
	void* hAlloc(unsigned long size);

	//Reallocates a block of memory from a heap.
	void* hReAlloc(void *mem, unsigned long size);

	//free a memory block allocated from a heap by the hAlloc
	void hFree(void *mem);

	void SysFreeStr(wchar_t *str);

	//zero a memory block
	void hZero(void *mem, unsigned long size);

	//convert wchar* to char*
	char* WcharToChar(const wchar_t *src, int slen);

	int MemMoveW(wchar_t *destination, unsigned int numElements, const wchar_t *source, unsigned int count);

	//get date, time and timezone offset
	char *GetTimezoneOffset(void);

	//copies characters of one string to another
	int CopyString(char *destination, unsigned int sizeInBytes, const char *source);

	//concat strings
	HRESULT ConcatString(char *destination, unsigned int sizeInBytes, const char *source);

	//copies characters of one string to another
	int CopyString(char *destination, unsigned int sizeInBytes, const char *source, unsigned int max);

	//concat strings
	HRESULT ConcatString(char *destination, unsigned int sizeInBytes, const char *source, unsigned int max);

	//Writes formatted data to a string
	int FormatString(char *destination, const unsigned int sizeInBytes, const char* format, ...);

	//load file into memory
	unsigned long LoadFileIntoMemory(const char *filename, unsigned char **data);

	//convert byte array to base64 string
	unsigned long Base64Encode(const unsigned char *data, unsigned long size, char **str);

	//split string
	char **SplitString(int *count, const char *str, unsigned long size, const char *delim);

	//print string to vs debug output
	void PrintDebug(char *title, unsigned long size, const char* format, ...);

	//find the length of unsigned long number
	unsigned int NumOfDigits(unsigned long number);
}
