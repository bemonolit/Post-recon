#include "prCommon.h"
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
	if (mem) HeapFree(processHeap, 0, mem);
}

//convert wide char to ascii char
char* Common::WcharToChar(const WCHAR *src, int slen)
{
	int len = 0;

	if ((len = WideCharToMultiByte(CP_ACP, 0, src, slen, NULL, 0, NULL, NULL)) == 0) {
		return NULL;
	}

	char *dest = (char*)hAlloc((len + 1) * sizeof(char));

	if (WideCharToMultiByte(CP_ACP, 0, src, slen, dest, len, NULL, NULL) == 0) {
		return NULL;
	}

	dest[len] = '\0';

	return dest;
}

HRESULT Common::generateMessageID(const char *sender, SIZE_T senderLength, char **messageID)
{
	GUID pGuiId;
	WCHAR sGuiId[64] = { 0 };
	WCHAR sTrimId[64] = { 0 };

	int strFromGuiSize = 0;
	char *senderCopy = 0;
	char domain[50] = { 0 };
	char *context = 0;
	char *sTrimIdA = 0;
	int messageIDSize = 0;

	//copy sender email
	senderCopy = (char*)hAlloc(senderLength * sizeof(char));
	if (senderCopy == NULL) {
		return S_FALSE;
	}
	if (strncpy_s(senderCopy, senderLength, sender, senderLength) != 0) {
		return S_FALSE;
	}

	//get first token
	if (strtok_s(senderCopy, "@", &context) == NULL) {
		hFree(senderCopy);
		return S_FALSE;
	}

	hFree(senderCopy);

	//Get email domain
	if (strcpy_s(domain, context) != 0) {
		return S_FALSE;
	}

	//Creates a GUID, a unique 128-bit integer.
	if (CoCreateGuid(&pGuiId) != S_OK) {
		return S_FALSE;
	}

	//Converts a globally unique identifier (GUID) into a string of printable characters.
	if ((strFromGuiSize = StringFromGUID2(pGuiId, sGuiId, _countof(sGuiId))) == 0) {
		return S_FALSE;
	}

	//Remove { and } from generated GUID
	if (wmemmove_s(sTrimId, 64, sGuiId + 1, strFromGuiSize - 3) != 0) {
		return S_FALSE;
	}

	sTrimId[strFromGuiSize - 3] = '\0';

	//convert GUID to ascii
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
	if (StringCbPrintfA(*messageID, messageIDSize, "%s", sTrimIdA) != S_OK) {
		hFree(sTrimIdA);
		return S_FALSE;
	}

	//concat @ e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@
	HRESULT result = StringCbPrintfA(*messageID + strlen(sTrimIdA), messageIDSize - strlen(sTrimIdA), "%s", "@");

	//concat domain e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	result = StringCbPrintfA(*messageID + strlen(sTrimIdA) + 1, messageIDSize - strlen(sTrimIdA) - 1, "%s", domain);

	hFree(sTrimIdA);

	return S_OK;
}
