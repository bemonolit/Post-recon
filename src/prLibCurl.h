#pragma once

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#define FROM    "xxxxxxxxxx@gmail.com"
#define TO      "yyyyyyyyyy@gmail.com"
//#define CC      "<info@example.org>"

typedef struct upload_status {
	int lines_read;
}upload_status;

namespace LibCurl
{
	size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp);
}
