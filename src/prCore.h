#pragma once

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

#include <windows.h>

#define _WIN32_WINNT_WIN10		0x0604

#define WIN_S03			0x0502
#define WIN_S08			0x0600
#define WIN_S08R2		0x0601
#define WIN_S12			0x0602
#define WIN_S12R2		0x0603
#define WIN_S16			0x0604

enum Architecture
{
	Arch_x86,
	Arch_Itanium,
	Arch_x64,
	Arch_Unknown
};

enum OSVersion
{
	Windows_Unknown,
	Windows_XP,
	Windows_XP64PRO,
	Windows_XPSP1,
	Windows_XPSP2,
	Windows_XPSP3,
	Windows_S2003,
	Windows_VISTA,
	Windows_VISTASP1,
	Windows_VISTASP2,
	Windows_S2008,
	Windows_S2008R2,
	Windows_7,
	Windows_7SP1,
	Windows_S2012,
	Windows_8,
	Windows_S2012R2,
	Windows_81,
	Windows_10,
	Windows_S2016
};

namespace Core
{
	//initialize core lib stuff
	void init(void);

	//un-initialize core lib stuff
	void uninit(void);

	//client unique id
	HRESULT UniqueID(char *id);
}
