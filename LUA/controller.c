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
	#include <linux/mm.h>
#endif
#include "controller.h"

/* the array 'supported_protocols' holds all pointers to the 
 * static and dynamic protocol buffers. It is filled by the 
 * call to register_protbuf */
static struct protocol_buf * supported_protocols[MAX_NR_OF_PROTOCOLS];

/* C_API: the function 'get_protocol_buf' returns the pointer 
 * to the protocol buffer of a given protocol id. */
struct protocol_buf * get_protocol_buf(uint32_t  protocol_id)
{
	return (struct protocol_buf *)supported_protocols[protocol_id];
}


/* LUA_INT: the function 'gc_packet_segment' is triggered by the 
 * garbage collector whenever a userdata annotated with one of 
 * the protocol buffer metatable should be collected. */
static int32_t gc_packet_segment(lua_State *L)
{
	lua_packet_segment * seg = (lua_packet_segment *)lua_touserdata(L, 1);
	if (seg && seg->changes) {
		seg->changes->ref_count--;
		if (seg->changes->ref_count <= 0) {
			kfree(seg->changes->field_length_changes);
			kfree(seg->changes->field_offset_changes);
			kfree(seg->changes);
			seg->changes = NULL;
		}
	}
	return 0;
}


/* LUA_API: the function 'set_raw' is used to set the bytes of a segment 
 * in 'raw' mode. The function is per default available in each protocol 
 * buffer until it gets overridden by a specific setter function inside 
 * a protocol buffer.
 * 
 * Parameters:
 * 1. lua_packet_segment (implicit)
 * 2. int32_t byte_value
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index, not used in this function
 *
 * Return: void
 */
static int32_t set_raw(lua_State *L)
{
	int32_t i;
	uint32_t  nob;
	uint8_t byte;
	uint8_t *ptr;
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	int32_t val = luaL_checkinteger(L, 2);

	nob = 1 << CHAR_BIT;

	luaL_argcheck(L, 0 <= val && val < nob, 2, "cannot cast value to char");

	byte = (uint8_t)val;
	ptr = seg->start + seg->offset;

	for (i = 0; i < seg->length; i++)
		ptr[i] = byte;

	return 0;
}

/* LUA_API: the function 'get_raw' is used to get the bytes of a segment 
 * in 'raw' mode. The function is per default available in each protocol 
 * buffer until it gets overridden by a specific getter function inside 
 * a protocol buffer.
 *
 * Parameters:
 * 1. lua_packet_segment (implicit)
 * 2. uint32_t  offset
 * 3. uint32_t  length 
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index, not used in this function
 *
 * Return: 
 * the byte array representing the given array
 */
static int32_t get_raw(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	init_byte_array(L, seg->start + seg->offset,  seg->length, 1);

	return 1;
}
/* LUA_API: The function 'get_segment' is used to get a new segment in 'raw' mode. 
 * Typically this function is applied on another raw segment in order 
 * to extract a part of the segment as new segment.
 *
 * Parameters:
 * 1.  lua_packet_segment, implicit through object oriented access seg:raw(..)
 * 2.  uint32_t  offset, this indicates where to start the new segment, see e.g below.
 * 3.  uint32_t  length, this indicates the size of the new segment
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index, not used in this function
 *
 * Return:
 * 1.  A lua_packet_segment annotated with the according metatable or False in
 *     case the input data is not valid
 *
 * Example:
 *
 * +------------------------+---------------------------------------+
 * | function call          | resulting lua_packet_segment          |
 * +========================+===+===+===+===+===+===+===+===+===+===+
 * | seg = packet:raw(0,10) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
 * +------------------------+---+---+---+---+---+---+---+---+---+---+
 * | 1st_half = seg:raw(0,5)| 0 | 1 | 2 | 3 | 4 |                   |
 * +------------------------+---+---+---+---+---+---+---+---+---+---+
 * | 2nd_half = seg:raw(5,5)|                   | 5 | 6 | 7 | 8 | 9 |
 * +------------------------+-------------------+---+---+---+---+---+
 */
static int32_t get_segment(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	uint32_t  offset = luaL_checkinteger(L, 2);
	uint32_t  length = luaL_checkinteger(L, 3);
	lua_packet_segment * new = (lua_packet_segment *)lua_newuserdata(L, sizeof(lua_packet_segment));

	new->start = seg->start;
	new->offset = seg->offset + offset;
	new->changes = NULL;
	/* we allow a seg->length == 0 , this enables processing packets where the packetsize is not fixed (0 = not fixed)*/
	if (seg->length != 0 && length > seg->length) {
		lua_pushboolean(L, 0);
		return 1;
	}

	new->length = length;
	luaL_getmetatable(L, prot_buf->name);
	lua_setmetatable(L, -2);

	return 1;
}

/* LUA_API: the function 'get_segment_size' is used to get the size of a segment.
 * 
 * Parameters:
 * 1.  lua_packet_segment, implicit through object oriented access seg:raw(..)
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index, not used in this function
 *
 * Return:
 * 1.  Size as lua_Number
 */
static int32_t get_segment_size(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushnumber(L, seg->length);
	return 1;
}

/* LUA_API: the function 'get_segment_offset' is used to get the real offset 
 * of a segment. This function returns the offset of the segment to the start
 * of the buffer. This means the following
 *     seg1 = packet:raw(2,10)
 *     seg2 = seg1:raw(3,5)
 *   offset = seg2:get_offset()
 *
 * will give an offset of 5, since the seg1 starts at offset 2, and seg2 starts
 * at offset (seg1:get_offset() + 3).
 * 
 * Parameters:
 * 1.  lua_packet_segment, implicit through object oriented access seg:raw(..)
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index, not used in this function
 *
 * Return:
 * 1.  Offset as lua_Number
 */
static int32_t get_segment_offset(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	lua_pushnumber(L, seg->offset);
	return 1;
}

/* LUA_API: overwrites the __tostring function of a lua_packet_segment.
 * this will print32_t a nicely formated string, including length,
 * offset and name of the protocol buffer.
 *
 * Parameters:
 * 1. lua_packet_segment (implicit)
 *
 * Returns:
 * 1. the representing string
 */
static int32_t packet_segment_tostring(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);
	int32_t n;
	char buf[128];

	n = sprintf(buf, "type: %s, offset: %d, length: %d", prot_buf->name, seg->offset, seg->length);
	lua_pushlstring(L, buf, n);

	return 1;
}


static const struct luaL_Reg seg_access_functions [] = {
	{ "set",	set_raw			},
	{ "get",	get_raw			},
	{ "raw",	get_segment		},
	{ "get_offset", get_segment_offset	},
	{ "get_size",	get_segment_size	},
	{ "to_bytes",	get_raw			},
	{ "__tostring", packet_segment_tostring },
	{ "__gc",	gc_packet_segment	},
	{ NULL,		NULL			}
};

/* C_API: the function 'get_metatable_from_protocol_type' is a helper
 * used in controller.c as well as it may find usage in the static 
 * protocol buffers and byte array implementation. */
void get_metatable_from_protocol_type(lua_State *L, int32_t type)
{
	char * table;
	lua_getglobal(L, SUPPORTED_PROTOCOL_TABLE);
	lua_rawgeti(L, -1, type);
	table = (char *)luaL_checkstring(L, -1);
	lua_pop(L, 2); /* pop the table SUPPORTED_PROTOCOL_TABLE and the string pushed by lua_gettable */
	luaL_getmetatable(L, table);
	return;
}

/* C_INT: the function 'payload_contains_protocol' is used internally. 
 * Depending if static or dynamic protocol buffer it calls the right
 * validation function. */
static int32_t payload_contains_protocol(lua_State *L, struct protocol_buf *prot_buf, lua_packet_segment *seg, uint32_t  prot_type)
{
	if (prot_buf->is_dynamic)
		return has_protocol_dynamic(L, prot_buf, seg, prot_type);
	else
		return prot_buf->has_protocol(L, prot_buf, seg, prot_type);
}

/* C_INT: the function 'protocol_get_field_changes' is used interally. 
 * It requests the field_changes struct calling the protocol buffers
 * 'get_field_changes' function. This funciton is called, whenever
 * the payload field with a given protocol type is requested inside 
 * the function 'get_protocol_field' */
static struct field_changes * protocol_get_field_changes(lua_State *L, struct protocol_buf *prot_buf, lua_packet_segment * seg)
{
	struct field_changes * changes = NULL;

	if (prot_buf->get_field_changes) {
		if (prot_buf->is_dynamic)
			changes = get_field_changes_dynamic(L, prot_buf, seg);
		else
			changes = prot_buf->get_field_changes(L, seg);
		 /* is already 1 when set by helper 'get_allocated_field_changes,
		  * since not every prot_buf may use this function we enforce it. */
		changes->ref_count = 1;
	}
	return changes;
}

/* C_INT: the function 'get_field_offset_in_bytes' wrapps the logic of 
 * calculating the new length with considering the optional field_changes. */
static int32_t get_field_offset_in_bytes(struct protocol_field * field, lua_packet_segment * seg, int32_t field_index)
{
	uint32_t  nr_of_bits, nr_of_bytes, field_offset;

	field_offset = field->offset;
	/* do we need to manipulate the default values stored inside the protocol buffer ?? */
	if (seg->changes)
		field_offset += seg->changes->field_offset_changes[field_index];
	/* how many bits remain */
	nr_of_bits = field_offset & (CHAR_BIT - 1);
	/* assuming CHAR_BIT == 2 ^ 3 */
	nr_of_bytes = (field_offset - nr_of_bits) >> 3;

	return seg->offset + nr_of_bytes;
}

/* C_INT: the function 'get_field_length_in_bytes' wrapps the logic of 
 * calculating the new offset with considering the optional field_changes. */
static int32_t get_field_length_in_bytes(struct protocol_field * field, lua_packet_segment * seg, int32_t field_index)
{
	uint32_t  nr_of_bits, nr_of_bytes, field_length;

	field_length = field->length;
	/* if the field length is smaller than 1 byte, we take the size of one byte
	 * we treat the case where field_length == 0 in a special way ...*/
	if (field_length < CHAR_BIT && field_length > 0)
		field_length = CHAR_BIT;

	/* do we need to manipulate the default values stored inside the protocol buffer ?? */
	if (seg->changes)
		field_length += seg->changes->field_length_changes[field_index];
	/* how many bits remain */
	nr_of_bits = field_length & (CHAR_BIT - 1);
	/* assuming CHAR_BIT == 2 ^ 3 */
	nr_of_bytes = (field_length - nr_of_bits) >> 3;
	return nr_of_bytes;
}

/* C_INT: the function 'initialize_field_getter_and_setter' initializes 
 * the setter and getter function of the field, considering the optional
 * field manipulator functions defined inside the protocol buffers. */
static void initialize_field_getter_and_setter(lua_State *L, struct protocol_buf *prot_buf, int32_t field_index)
{
	/* lets check if there is a metatable on top of the stack */
	struct protocol_field * f = (struct protocol_field *)&prot_buf->protocol_fields[field_index];

	if (!lua_istable(L, -1)) luaL_error(L, "cannot initialize getter and setter for field %s->%s, "
					    "not a table on top of the stack, is '%s'", prot_buf->name, f->name, lua_typename(L, lua_type(L, -1)));

	/* is there a 'getter' to initialize ? */
	lua_pushlightuserdata(L, prot_buf);     /* push upvalue 1 */
	lua_pushinteger(L, field_index);        /* push upvalue 2 */
	if (f->get) {
		if (prot_buf->is_dynamic)
			lua_pushcclosure(L, field_dynamic_getter, 2);
		else
			lua_pushcclosure(L, f->get, 2);
	}else
		/* there is no specific getter defined - fall back to 'get_raw'  */
		lua_pushcclosure(L, get_raw, 2);
	 /* set the metatable field 'get' */
	lua_setfield(L, -2, "get");

	/* is there a 'setter' to initialize ? */
	lua_pushlightuserdata(L, prot_buf);     /* push upvalue 1 */
	lua_pushinteger(L, field_index);        /* push upvalue 2 */
	if (f->set) {
		if (prot_buf->is_dynamic)
			lua_pushcclosure(L, field_dynamic_setter, 2);
		else
			lua_pushcclosure(L, f->set, 2);
	}else
		/* there is no specific setter defined - fall back to 'set_raw'  */
		lua_pushcclosure(L, set_raw, 2);
	 /* set the metatable field 'set' */
	lua_setfield(L, -2, "set");
}

/* LUA_API: 'get_protocol_field' is used in Lua as a closure for each field of a protocol
 * buffer. E.g a call to ip = packet:data(packet_ip) will go to this function,
 * and trigger the conversion of the raw packet to a ip packet. Each call
 * to a field function of an IP packet, like ip:daddr() uses this function
 * to to return the right data. In each case you will end up either with a
 * new packet segment (annotated with the proper metatable) or a boolean
 * value (False) if something went wrong. In the case everything went fine,
 * the newly created lua_packet_segment is annotated with the proper
 * metatable where the fields get and set also contain the specific getter
 * and setter functions given by the protocol buffer. E.g. the function call
 * ip:daddr():get() or ip:daddr():set(...) will call the proper function
 * defined inside the corresponding field definition.
 *
 * Parameters:
 * 1.  lua_packet_segment, implicit through object oriented access seg:raw(..)
 * 2.  type of the protocol buffer, optional, and only used if the accessed
 *     field is the payload field. If a type is provided for the access of the
 *     payload field, the function tries to convert the data pointed to by the
 *     payload field to the given type. To check if such a conversion is
 *     possible, it calls the function pointed to by the protocol buffer member
 *     has_protocol. If this function returns True, the conversion takes place.
 *
 * Upvalues:
 * 1.  struct protocol_buf*
 * 2.  int32_t field index
 *
 * Return:
 * 1.  A lua_packet_segment annotated with the according metatable or False in
 *     case the input data is not valid
 */
static int32_t get_protocol_field(lua_State *L)
{
	int32_t prot_type;
	lua_packet_segment * seg, *new;
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	int32_t field_index = lua_tointeger(L, lua_upvalueindex(2));
	struct protocol_field * field = &prot_buf->protocol_fields[field_index];

	/* get the current packet segment */
	seg = checkpacketseg(L, 1, prot_buf->name);

	/* initialize the new packet segment */
	new = (lua_packet_segment *)lua_newuserdata(L, sizeof(lua_packet_segment));
	new->start = seg->start;         /* the start is unchanged */
	new->offset = get_field_offset_in_bytes(field, seg, field_index);
	new->length = get_field_length_in_bytes(field, seg, field_index);

	/* if new->length == 0 then no configuration was done, we guess the size by subtracting the
	 * new offset from the packet length. since the old length is getting initialized by the
	 * netfilter extension this assumption holds for the very last field of the protocol.
	 * this 'feature' should be used by protocol buffers containing a payload, whereas the
	 * payload field is the last field of the buffer. However, at compile-time unknown field
	 * sizes (and offsets) of fields not being placed at the end of the protocol should be
	 * initialized using the 'get_field_changes' hook system. */
	if (new->length == 0)
		new->length = (seg->length + seg->offset) - (new->offset);
	         /*
	                         printf("%s->%s:: seg->offset %i, seg->length %i, new->offset %i, new->length %i\n",
	                                         prot_buf->name, field->name, seg->offset, seg->length, new->offset, new->length);
	          */
	/* special care for packet payload requests */
	if (prot_buf->payload_field != NULL && strcmp(prot_buf->payload_field, field->name) == 0) {
		/* we know the payload field is requested */
		/* the requested payload can be delivered either as a common segment or as
		 * an other packet type, such a conversion needs an extra protocol parameter
		 * ... so lets check */

		if (lua_isnumber(L, 2)) {
			/* we have an extra parameter, ... lets see if it is a valid protocol
			 * the parameter is the index of the 'supported_protocols'-array member */
			prot_type = lua_tointeger(L, 2);
			if (prot_type >= 0 && prot_type < PACKET_SENTINEL) {
				/* we are sure the purpose of the request is to get the payload data,
				 * converted to the given protocol.  lets check if the payload contains
				 * data of the given protocol */
				if (payload_contains_protocol(L, prot_buf, seg, prot_type)) {
					/* success, we can  push the metatable for the given protocol */
					get_metatable_from_protocol_type(L, prot_type);
					if (!lua_isnil(L, -1))  /* check if the metatable was found */
						/* perhaps the field offsets and lengths of the containing protocol
						 * are not set correctly. request the optional 'field_changes' structure
						 * holding the changes for lengths and offsets. */
						new->changes = protocol_get_field_changes(L, get_protocol_buf(prot_type), new);
					else{
						/* failed, the requested protocol is not available
						 * we push false and return */
						lua_pop(L, 1); /* pop the userdata */
						lua_pushboolean(L, 0);
						return 1;
					}
				}else{
					/* payload does not carry the provided protocol */
					/* we push false and return */
					lua_pop(L, 1); /* pop the userdata */
					lua_pushboolean(L, 0);
					return 1;
				}
			}else{
				/* unknown protocol */
				lua_pop(L, 1); /* pop the userdata */
				luaL_error(L, "provided protocol is unknown");
			}
		}
	}

	/* if there is still the 'new' userdata on the top, we push our own metatable */
	if (lua_isuserdata(L, -1)) {
		luaL_getmetatable(L, prot_buf->name);
		new->changes = seg->changes;
		if (seg->changes)
			new->changes->ref_count++;
	}

	/* a new packet segment is at index -2 , and the proper metatable at index -1 of the stack
	 * lets set the propper setter and getter function for the requested field */
	initialize_field_getter_and_setter(L, prot_buf, field_index);

	lua_setmetatable(L, -2);
	return 1;
}

/* C_API: 'register_protbuf' is only used internally. This function takes a
 * pointer to a fully initialized protocol buffer struct and registers it
 * inside the Lua state. Registering means:
 *
 * 1.  it creates a new metatable with the name of the protocol buffer.
 * 2.  it registers the default functions which are stored in the luaL_Reg
 *     array seg_access_functions.
 * 3.  it loops over the protocol fields stored at prot_buf->protocol_fields
 *     and registers a new function (using the field name) inside the
 *     metatable. Each field points to the function 'get_protocol_field'
 *     which acts as a closure taking a pointer to the protocol buffer as
 *     well as the index of the field as upvalues.
 * 4.  The protocol index, serves as numerical identifier of this protocol
 *     buffer or even of the protocol itself. This index is stored as a
 *     global value inside the Lua state as well as inside the Lua table
 *     'supported_protocols'. Assuming the name of a procotol buffer is
 *     "packet_ip" the following statements are true:
 * 
 *       supported_protocols[protocol_index] == "packet_ip"
 *                                 packet_ip == protocol_index
 *
 *     This allows you to get all registered protocols from within Lua. This
 *     is especially usefull for the dynamic protocol buffers where you have
 *     to provide your own "has_protocol"-function, which probably needs the
 *     information on which protocols it is able to contain.
 */
void register_protbuf(lua_State *L, struct protocol_buf * prot_buf, uint32_t  protocol_index)
{
	int32_t field_index;
	luaL_Reg *reg = (struct luaL_Reg *)seg_access_functions;
	struct protocol_field * field = prot_buf->protocol_fields;

	luaL_newmetatable(L, prot_buf->name);

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);   /* duplicates the metatable */
	lua_setfield(L, -2, "__index");

	/* pushing default functions */
	for (; reg->name; reg++) {
		lua_pushlightuserdata(L, (void *)prot_buf);
		lua_pushcclosure(L, reg->func, 1);
		lua_setfield(L, -2, reg->name);
	}

	/* pushing functions specific to the protocol buffer */
	for (field_index = 0; field->name; field++, field_index++) {
		lua_pushlightuserdata(L, (void *)prot_buf);             /* upvalue: prot_buf */
		lua_pushinteger(L, field_index);                        /* upvalue: index of protocol field */
		lua_pushcclosure(L, get_protocol_field, 2);
		lua_setfield(L, -2, field->name);
	}
	/* pop the metatable */
	lua_pop(L, 1);

	/* registering the array-index as the protocol_id*/
	lua_getglobal(L, "_G");
	lua_pushinteger(L, protocol_index);
	lua_setfield(L, -2, prot_buf->name);
	lua_pop(L, 1); /* pop _G */

	lua_getglobal(L, SUPPORTED_PROTOCOL_TABLE);
	lua_pushstring(L, prot_buf->name);
	lua_rawseti(L, -2, protocol_index);

	lua_pop(L, 1);  /* pop SUPPORTED_PROTOCOL_TABLE */

	supported_protocols[protocol_index] = prot_buf;
}

void luaopen_controller(lua_State *L)
{
	/* registering a table inside the _G with table[protocol_index] = prot_buf->name */
	lua_getglobal(L, "_G");
	lua_newtable(L);
	lua_setfield(L, -2, SUPPORTED_PROTOCOL_TABLE);
	lua_pop(L, 1); /* pop _G */                   
	
	luaopen_protbuf_raw(L);
	luaopen_protbuf_eth(L);
	luaopen_protbuf_ip(L);
	luaopen_protbuf_icmp(L);
	luaopen_protbuf_tcp(L);
	luaopen_protbuf_tcp_options(L);
	luaopen_protbuf_udp(L);
	luaopen_protbuf_tftp(L);
	luaopen_protbuf_dynamic(L);
	/* should follow all other static buffers */
#if defined(__KERNEL__)
	luaopen_nflib(L);
#endif

	luaopen_bytearraylib(L);
}




