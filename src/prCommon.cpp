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

void Common::init(void)
{
	//retrieve a handle to the default heap of this process
	processHeap = GetProcessHeap();
}

void* Common::hAlloc(SIZE_T size)
{
	if (size == 0) return NULL;
	//allocate a block of memory from a heap
	return HeapAlloc(processHeap, HEAP_ZERO_MEMORY, size);
}

void Common::hFree(void *mem)
{
	//free a memory block allocated from a heap by the HeapAlloc
	if (mem) {
		HeapFree(processHeap, 0, mem);
		mem = NULL;
	}
}

void Common::hZero(void *mem, SIZE_T size)
{
	//Fills a block of memory with zeros. 
	if (mem) SecureZeroMemory(mem, size);
}

//convert wide char to ascii char
char* Common::WcharToChar(const WCHAR *src, int slen)
{
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
	GUID pGuiId;
	WCHAR sGuiId[64] = { 0 };
	WCHAR sTrimId[64] = { 0 };

	int strFromGuiSize = 0;
	char *senderCopy = 0;
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

	if (strncpy_s(senderCopy, senderLength + 1, sender, senderLength) != 0) {
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

	if (strcpy_s(domain, tmp) != 0) {
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
	//if (StringCbPrintfA(*messageID, messageIDSize, "%s", sTrimIdA) != S_OK) {
	if (_snprintf_s(*messageID, messageIDSize, _TRUNCATE, "%s", sTrimIdA) == -1) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//concat @ e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@
	//if (StringCbPrintfA(*messageID + strlen(sTrimIdA), messageIDSize - strlen(sTrimIdA), "%s", "@") != S_OK) {
	if (_snprintf_s(*messageID + strlen(sTrimIdA), messageIDSize - strlen(sTrimIdA), _TRUNCATE, "%s", "@") == -1) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//concat domain e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	//if (StringCbPrintfA(*messageID + strlen(sTrimIdA) + 1, messageIDSize - strlen(sTrimIdA) - 1, "%s", domain) != S_OK) {
	if (_snprintf_s(*messageID + strlen(sTrimIdA) + 1, messageIDSize - strlen(sTrimIdA) - 1, _TRUNCATE, "%s", domain) == -1) {
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

