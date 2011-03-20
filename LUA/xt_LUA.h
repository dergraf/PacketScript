/*
 *	Copyright (C) 2010 University of Basel <http://cn.cs.unibas.ch/>
 *	by Andre Graf <andre.graf@stud.unibas.ch>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XT_LUA_H_
#define XT_LUA_H_

#define MAX_FILENAME_SIZE  256
#define MAX_FUNCTION_SIZE  256
#define MAX_SCRIPT_SIZE 32768
#define LUA_STATE_ARRAY_SIZE 128

/* the targetsize is stored in a u16, so max size of the xt_lua_tginfo cannot exceed 64K*/
struct xt_lua_tginfo {
	char buf[MAX_SCRIPT_SIZE];
	char filename[MAX_FILENAME_SIZE];
	char function[MAX_FUNCTION_SIZE];
	__u64 script_size;
	__u32 state_id;
};

#endif /* XT_LUA_H_ */
