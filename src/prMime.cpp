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
#include "prMime.h"
#include <stdio.h>

//works only for reading new/unseen emails(not forwarded or replied) from gmail. (utf8)
HRESULT Mime::ParseMime(MimeMessage *msg, const char *raw_data, int rawDataSize)
{
	char **splittedString = 0;
	int splitted = 0;
	int i = 0;
	int equalIndex = 0;
	int carriageIndex = 0;
	char boundary[256] = "--";
	char *tmp = 0;

	if ((splittedString = Common::SplitString(&splitted, raw_data, rawDataSize, "\n")) != NULL) {
		for (i = 0; i < splitted; i++) {

			//extract boundary value
			if (strstr(splittedString[i], "boundary") != NULL) {
				equalIndex = strcspn(splittedString[i], "=");
				carriageIndex = strcspn(splittedString[i], "\r");
				if (Common::ConcatString(boundary, sizeof(boundary), splittedString[i] + equalIndex + 1, carriageIndex - equalIndex - 1) == S_FALSE) {
					break;
				}
			}

			//body message begins
			if (strstr(splittedString[i], "Content-Type: text/plain; charset=UTF-8") != NULL) {
				//ignore next empty line
				i += 2;
				//read till boundary
				while (strstr(splittedString[i], boundary) == NULL && i < splitted) {
					//ignore empty lines
					if (_stricmp(splittedString[i], "\r") != 0) {
						if (msg->body == NULL) {
							if ((msg->body = (char*)Common::hAlloc(strlen(splittedString[i]) * sizeof(char))) == NULL) {
								break;
							}
							carriageIndex = strcspn(splittedString[i], "\r");
							if (Common::CopyString(msg->body, strlen(splittedString[i]), splittedString[i], carriageIndex) == S_FALSE) {
								break;
							}
						}
						else {
							if ((tmp = (char*)Common::hReAlloc(msg->body, strlen(msg->body) + strlen(splittedString[i]) * sizeof(char))) == NULL) {
								break;
							}
							msg->body = tmp;
							carriageIndex = strcspn(splittedString[i], "\r");
							if (Common::ConcatString(msg->body, strlen(msg->body) + strlen(splittedString[i]), splittedString[i], carriageIndex) == S_FALSE) {
								break;
							}
						}
					}
					i++;
				}
				//stop reading
				break;
			}
		}

		for (i = 0; i < splitted; i++) {
			Common::hFree(splittedString[i]);
		}
		Common::hFree(splittedString);
	}

	return S_OK;
}
