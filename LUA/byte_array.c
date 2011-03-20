/*
 *	Copyright (C) 2010 University of Basel <http://cn.cs.unibas.ch/>
 *	by Andre Graf <andre@dergraf.org>
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
#include "controller.h"

/* Initialization helper function. This function should be used whenever
 * a new byte array need to be initialized. Depending on the arguments it
 * initializes the array in a different way. Have a look at the inline
 * comments */
lua_packet_segment * init_byte_array(lua_State *L, unsigned char * start, int length, int do_copy)
{
	lua_packet_segment *array;

	if (length < 0)
		luaL_error(L, "init_byte_array, requested size < 0");

	if (start && do_copy) {
		/* we have a start address where we copy from */
		array = lua_newuserdata(L, sizeof(lua_packet_segment) + length);
		array->start = (unsigned char *)array + sizeof(lua_packet_segment); /* aligning pointer */
		memcpy(array->start, start, length);
	}else if (start && !do_copy) {
		/* just link the start pointer, in this case you have to free the memory yourself */
		array = lua_newuserdata(L, sizeof(lua_packet_segment));
		array->start = start;
	}else{
		/* create an empty array, fully managed by Lua */
		array = lua_newuserdata(L, sizeof(lua_packet_segment) + length);
		array->start = (unsigned char *)array + sizeof(lua_packet_segment); /* aligning pointer */
		memset(array->start, 0, length);
	}

	array->length = length;
	array->offset = 0;
	array->changes = NULL;

	luaL_getmetatable(L, LUA_BYTE_ARRAY);
	lua_setmetatable(L, -2);

	return array;
}



/* LUA_API: get one byte of the given byte array 
 * access-pattern: array[<index>] */
static int32_t get_byte_array(lua_State *L)
{
	lua_packet_segment * array = checkbytearray(L, 1);
	int32_t index = luaL_checkinteger(L, 2); /* array starts with index 0 (not 1 as usual in Lua) */

	luaL_argcheck(L, 0 <= index && index < array->length, 1, "index out of range");
	lua_pushinteger(L, (array->start + array->offset)[index]);

	return 1;
}

/* LUA_API: set one byte of the given byte array
 * access-pattern: array[<index>]= 0xFF */
static int32_t set_byte_array(lua_State *L)
{
	lua_packet_segment * array = checkbytearray(L, 1);
	uint8_t byte;
	int32_t index = luaL_checkinteger(L, 2);    /* array starts with index 0 (not 1 as usual in Lua) */
	int32_t val = luaL_checkinteger(L, 3);
	uint32_t  nob = 1 << CHAR_BIT;               /* we should use something like 1 << CHAR_BIT */

	luaL_argcheck(L, 0 <= index && index < array->length, 1, "index out of range");
	luaL_argcheck(L, 0 <= val && val < nob, 2, "cannot cast value to char");

	byte = (uint8_t)val;

	(array->start + array->offset)[index] = byte;

	return 0;
}

/* LUA_API: get size of the given byte array
 * access-pattern: #array (__length meta-method) */
static int32_t get_byte_array_size(lua_State *L)
{
	lua_packet_segment * array = checkbytearray(L, 1);

	lua_pushnumber(L, array->length);

	return 1;
}


/* LUA_API: converts a given byte array to a string. 
 * access-pattern: implicit through functions calling the
 * __to_string() metamethod , e.g. print32_t */
static int32_t byte_array_to_string(lua_State *L)
{
	lua_packet_segment * array = checkbytearray(L, 1);
	uint8_t buf[(array->length * 3) + 255];
	uint8_t hexval[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	char res[255 + (array->length * 3)]; /* make sure the buffer is big enough*/
	int32_t i, n;
	uint8_t *ptr = array->start + array->offset;

	for (i = 0; i < array->length; i++) {
		buf[i * 3] = hexval[(ptr[i] >> 4) & 0xF];
		buf[(i * 3) + 1] = hexval[ptr[i] & 0x0F];
		buf[(i * 3) + 2] = ' '; /* seperator */
	}

	buf[array->length * 3] = '\0';
	n = sprintf(res, "byte_array: length: %d  value: %s", array->length, buf);

	lua_pushlstring(L, res, n);

	return 1;
}

static const struct luaL_Reg bytearray_lib_m [] = {
	{ "__len",	get_byte_array_size  },
	{ "__newindex", set_byte_array	     },
	{ "__index",	get_byte_array	     },
	{ "__tostring", byte_array_to_string },
	{ NULL,		NULL		     }
};

void luaopen_bytearraylib(lua_State *L)
{
	luaL_newmetatable(L, LUA_BYTE_ARRAY);
	luaL_register(L, NULL, bytearray_lib_m);
	lua_pop(L, 1);
}


