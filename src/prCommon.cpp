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

#include "prCommon.h"

#include <time.h>
#include <wchar.h>
#include <Strsafe.h>

static HANDLE processHeap;

//retrieve a handle to the default heap of this process
void Common::init(void)
{
	processHeap = GetProcessHeap();
}

//allocate a block of memory from a heap
void* Common::hAlloc(SIZE_T size)
{
	if (processHeap == NULL || size <= 0) return NULL;

	return HeapAlloc(processHeap, HEAP_ZERO_MEMORY, size);
}

//free a memory block allocated from a heap by the HeapAlloc
void Common::hFree(void *mem)
{
	if (processHeap == NULL || mem == NULL) return;

	HeapFree(processHeap, 0, mem);
	mem = NULL;
}

//Fills a block of memory with zeros. 
void Common::hZero(void *mem, SIZE_T size)
{
	if (size <= 0)return;

	if (mem) {
		SecureZeroMemory(mem, size);
	}
}

//convert wide char to ascii char
char* Common::WcharToChar(const WCHAR *src, int slen)
{
	if (src == NULL || slen <= 0)return NULL;

	int len = 0;

	//Maps a UTF-16 (wide character) string to a new character string. 
	//The new character string is not necessarily from a multibyte character set. 
	//return the required buffer size
	if ((len = WideCharToMultiByte(CP_ACP, 0, src, slen, NULL, 0, NULL, NULL)) == 0) {
		return NULL;
	}

	char *dest = (char*)hAlloc((len + 1) * sizeof(char));

	//convert
	if (WideCharToMultiByte(CP_ACP, 0, src, slen, dest, len, NULL, NULL) == 0) {
		return NULL;
	}

	dest[len] = '\0';

	return dest;
}

HRESULT Common::GenerateMessageID(const char *sender, SIZE_T senderLength, char **messageID)
{
	if (sender == NULL || senderLength <= 0)return S_FALSE;

	GUID pGuiId;
	WCHAR sGuiId[64] = { 0 };
	WCHAR sTrimId[64] = { 0 };

	int strFromGuiSize = 0;
	char *senderCopy = 0;
	int domainSize = 50;
	char domain[50] = { 0 };
	char *context = 0;
	char *tmp = 0;
	char *sTrimIdA = 0;
	int messageIDSize = 0;

	//copy sender email
	senderCopy = (char*)hAlloc((senderLength + 1) * sizeof(char));
	if (senderCopy == NULL) {
		return S_FALSE;
	}

	if (Common::CopyString(senderCopy, senderLength + 1, sender) != 0) {
		hFree(senderCopy);
		return S_FALSE;
	}

	//get first token
	if (strtok_s(senderCopy, "@", &context) == NULL) {
		hFree(senderCopy);
		return S_FALSE;
	}

	//Get email domain
	if ((tmp = strtok_s(NULL, "@", &context)) == NULL) {
		hFree(senderCopy);
		return S_FALSE;
	}

	if (Common::CopyString(domain, domainSize, tmp) != 0) {
		hFree(senderCopy);
		return S_FALSE;
	}

	hFree(senderCopy);

	//Create a GUID, a unique 128-bit integer.
	if (CoCreateGuid(&pGuiId) != S_OK) {
		return S_FALSE;
	}

	//Convert a globally unique identifier (GUID) into a string of printable characters.
	if ((strFromGuiSize = StringFromGUID2(pGuiId, sGuiId, _countof(sGuiId))) == 0) {
		return S_FALSE;
	}

	//Remove { and } from generated GUID
	if (wmemmove_s(sTrimId, 64, sGuiId + 1, strFromGuiSize - 3) != 0) {
		return S_FALSE;
	}

	sTrimId[strFromGuiSize - 3] = '\0';

	//Convert GUID to ascii
	sTrimIdA = WcharToChar(sTrimId, 64);
	if (sTrimIdA == NULL) {
		return S_FALSE;
	}

	//messageID will store the final message-id value
	messageIDSize = strlen(sTrimIdA) + 1 + strlen(domain) + 1;

	*messageID = (char*)hAlloc(messageIDSize * sizeof(char));
	if (*messageID == NULL) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//copy trimmed guid to messageid e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if (Common::FormatString(*messageID, messageIDSize, "%s", sTrimIdA) == -1) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//concat @ e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@
	if (Common::FormatString(*messageID + strlen(sTrimIdA), messageIDSize - strlen(sTrimIdA), "%s", "@") == -1) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//concat domain e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	if (Common::FormatString(*messageID + strlen(sTrimIdA) + 1, messageIDSize - strlen(sTrimIdA) - 1, "%s", domain) == -1) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	hFree(sTrimIdA);

	return S_OK;
}

char* Common::GetTimezoneOffset(void)
{
	struct tm lcl;
	struct tm gmt;

	char *dateTime = (char*)Common::hAlloc(50 * sizeof(char));
	if (dateTime == NULL) {
		return NULL;
	}

	time_t now = time(NULL);

	if (!now) return NULL;

	localtime_s(&lcl, &now);
	time_t local = mktime(&lcl);

	if (!local) return NULL;

	gmtime_s(&gmt, &now);
	time_t utc = mktime(&gmt);

	if (!utc) return NULL;

	//Mon, 29 Nov 2010 21:54:29 +1100
	if (strftime(dateTime, 50, "%a, %d %b %Y %H:%M:%S %z", &gmt) == 0) {
		return NULL;
	}

	return dateTime;
}

//copy string
int Common::CopyString(char *destination, size_t sizeInBytes, const char *source)
{
	if (destination == NULL || sizeInBytes <= 0 || source == NULL) return EINVAL;

	return strncpy_s(destination, sizeInBytes, source, _TRUNCATE);
}

//format string
int Common::FormatString(char *destination, const size_t sizeInBytes, char const* const format, ...)
{
	if (destination == NULL || sizeInBytes <= 0 || format == NULL) return -1;

	int result = -1;

	va_list argList;
	va_start(argList, format);
	result = _vsnprintf_s(destination, sizeInBytes, _TRUNCATE, format, argList);
	va_end(argList);

	return result;
}

unsigned long Common::LoadFileIntoMemory(const char *filename, unsigned char **data)
{
	if (filename == NULL) return -1;

	unsigned long size;
	HANDLE hFile;
	LARGE_INTEGER filesize;
	unsigned long bytesRead;

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	if (GetFileSizeEx(hFile, &filesize) == 0) {
		CloseHandle(hFile);
		return -1;
	}

	if (filesize.HighPart != 0) {
		CloseHandle(hFile);
		return -1;
	}

	size = filesize.LowPart;

	if ((*data = (unsigned char*)Common::hAlloc(size * sizeof(unsigned char))) == NULL) {
		CloseHandle(hFile);
		return -1;
	}

	if (ReadFile(hFile, *data, size, &bytesRead, NULL) == 0) {
		Common::hFree(*data);
		CloseHandle(hFile);
		return -1;
	}

	if (size != bytesRead) {
		Common::hFree(*data);
		CloseHandle(hFile);
		return -1;
	}

	CloseHandle(hFile);

	return size;
}

//convert byte array to base64 string
unsigned long Common::Base64Encode(const unsigned char *data, unsigned long size, char **str)
{
	if (data == NULL || size <= 0) return -1;

	unsigned long bytesWritten = 0;

	if (CryptBinaryToString(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &bytesWritten) == 0) {
		return -1;
	}

	if ((*str = (char*)Common::hAlloc(bytesWritten * sizeof(char))) == NULL) {
		return -1;
	}

	if (CryptBinaryToString(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *str, &bytesWritten) == 0) {
		Common::hFree(*str);
		return -1;
	}

	return bytesWritten;
}
