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

#if defined(__KERNEL__)
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>         /* kmalloc */
#endif

#include "controller.h"

int32_t get_header_size(struct protocol_buf * prot_buf)
{
	int32_t bit_counter = 0;
	struct protocol_field * field = prot_buf->protocol_fields;

	for (; field->name; field++)
		bit_counter += field->length;

	return bit_counter >> 3;
}


int32_t set_32_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	*(uint32_t  *)(seg->start + seg->offset) = (uint32_t  )htonl(luaL_checkinteger(L, 2));
	return 0;
}
int32_t get_32_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushinteger(L, ntohl(*((uint32_t  *)(seg->start + seg->offset))));
	return 1;
}

int32_t set_16_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	*(uint16_t *)(seg->start + seg->offset) = (uint16_t)htons(luaL_checkinteger(L, 2));
	return 0;
}
int32_t get_16_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushinteger(L, ntohs(*((uint16_t *)(seg->start + seg->offset))));
	return 1;
}

int32_t set_lower_4_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	uint8_t b = (uint8_t)luaL_checkinteger(L, 2) << 4;
	uint8_t * pos = (uint8_t *)(seg->start + seg->offset);

	*pos &= 0x0F; /* reset lower 4 bits*/
	*pos |= b;

	return 0;
}

int32_t get_lower_4_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushinteger(L, (*(uint8_t *)(seg->start + seg->offset)) >> 4);
	return 1;
}

int32_t set_upper_4_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	uint8_t b = (uint8_t)luaL_checkinteger(L, 2) << 4;
	uint8_t * pos = (uint8_t *)(seg->start + seg->offset);

	*pos &= 0xF0; /* reset upper 4 bits*/
	*pos |= (b >> 4);

	return 0;
}

int32_t get_upper_4_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushinteger(L, (*(uint8_t *)(seg->start + seg->offset)) & 0x0F);
	return 1;
}


int32_t set_8_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	*(uint8_t *)(seg->start + seg->offset) = (uint8_t)luaL_checkinteger(L, 2);
	return 0;
}

int32_t get_8_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushinteger(L, *(uint8_t *)(seg->start + seg->offset));
	return 1;
}

int32_t set_1_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	unsigned long l = 0;

	memcpy(&l, (seg->start + seg->offset), seg->length);
	l |= (1 << ((CHAR_BIT * seg->length) - luaL_checkinteger(L, 2)));
	memcpy((seg->start + seg->offset), &l, seg->length);

	return 0;
}

int32_t get_1_bit_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	unsigned long l = 0;
	uint32_t  bit = 0;

	memcpy(&l, (seg->start + seg->offset), seg->length);
	bit = l & (1 << ((CHAR_BIT * seg->length) - luaL_checkinteger(L, 2)));

	lua_pushboolean(L, bit);
	return 1;
}

int32_t get_string_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
    
	/* Warning we cast from uchar to char */
	lua_pushlstring(L, (char *)seg->start + seg->offset, seg->length);
	return 1;
}

int32_t set_data_generic(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	lua_packet_segment * data = checkbytearray(L, 2);

	pr_debug("seg->length %u, data->length %u\n", seg->length, data->length);

	if (seg->length >= data->length)
		memcpy((seg->start + seg->offset), data->start, data->length);
	else
		luaL_error(L, "provided byte array too big for given packet segment");
	return 0;
}

struct field_changes * get_allocated_field_changes(lua_State *L, int32_t nr_of_fields)
{
	struct field_changes * changes;

	changes = kmalloc(sizeof(struct field_changes), GFP_ATOMIC);

	if (!changes)
		goto failure;

	changes->field_length_changes = kmalloc(nr_of_fields * sizeof(int), GFP_ATOMIC);
	if (!changes->field_length_changes)
		goto free1;

	changes->field_offset_changes = kmalloc(nr_of_fields * sizeof(int), GFP_ATOMIC);
	if (!changes->field_offset_changes)
		goto free2;

	memset(changes->field_length_changes, 0, nr_of_fields * sizeof(int));
	memset(changes->field_offset_changes, 0, nr_of_fields * sizeof(int));

	changes->ref_count = 1;

	return changes;

free2: kfree(changes->field_length_changes);
free1: kfree(changes);
failure:
	if (!changes) luaL_error(L, "couldnt allocate memory inside 'get_allocated_field_changes'");
	return NULL; /* only to omit warnings */
}