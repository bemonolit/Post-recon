#include <Windows.h>
#include "prLibCurl.h"

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

#define TO "xxxxxxxxxx@gmail.com"
#define FROM "yyyyyyyy@gmail.com"
#define NAME "Joe Doe"
#define PASSWORD "zzzzzzzzzzzzzz"

int main(void)
{
	char subject[50] = "Hello there";
	char body[100] = "Test body\r\nnew line\r\ntest test\r\ntest";

	LibCurl::SendEmail(FROM, NAME, TO, subject, body, PASSWORD, TRUE, "");

	return EXIT_SUCCESS;
}
