#pragma once
#include <windows.h>

namespace Common
{
	//initialize common lib stuff
	void init(void);

	//Allocates a block of memory from a heap.
	void* hAlloc(SIZE_T size);

	//free a memory block allocated from a heap by the hAlloc
	void hFree(void *mem);

	//convert wchar* to char*
	char* WcharToChar(const WCHAR *src, int slen);

	//generate a new Message-ID for email.
	HRESULT generateMessageID(const char *sender, SIZE_T senderLength, char **messageID);
}
