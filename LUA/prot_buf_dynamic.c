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



struct protocol_buf * dyn_prot_buf_array[MAX_NR_OF_DYN_PROT_BUFS] = { NULL }; 


/* LUA_API: the function 'field_dynamic_setter' acts as a wrapper around
 * a given Lua field setter function of a dynamic protocol buffer. The 
 * string containing the lua function name was piggybacked in the 'set'
 * member of the protocol_field. We call this function passing the actual
 * segment as byte array and the set value.
 * 
 * Paramters:
 * 1.  lua_packet_segment (implicit)
 * 2.  some lua value 
 *
 * Upvalues:
 * 1.  pointer to the protocol buffer 
 * 2.  field index 
 *
 * Returns:
 * 1.  true or false if the 'set' was successful
 */
int32_t field_dynamic_setter(lua_State *L)
{
	size_t nbytes;
	lua_packet_segment * array;
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	int32_t field_index = lua_tointeger(L, lua_upvalueindex(2));
    
	/* the function name is piggybacked as a string */
	lua_getglobal(L, (char *)prot_buf->protocol_fields[field_index].set);
	if (!lua_isfunction(L, -1)) {
		lua_pushboolean(L, 0);
		return 1;
	}

	nbytes = sizeof(lua_packet_segment) + seg->length * sizeof(uint8_t);
	array = (lua_packet_segment *)lua_newuserdata(L, nbytes);
	array->length = seg->length;
	array->start = seg->start + seg->offset;
	array->changes = NULL;

	luaL_getmetatable(L, LUA_BYTE_ARRAY);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, 2); /* push value to set */
	if (lua_pcall(L, 2, 1, 0) != 0) {
		pr_debug("Error: %s \n", lua_tostring(L, -1));
		lua_pop(L, 1);
		lua_pushboolean(L, 0);
	}
	return 1;
}

/* LUA_API: the function 'field_dynamic_getter' acts as a wrapper around
 * a given Lua field getter function of a dynamic protocol buffer. The 
 * string containing the lua function name was piggybacked in the 'get'
 * member of the protocol_field. We call this function passing the actual
 * segment as byte array.
 * 
 * Paramters:
 * 1.  lua_packet_segment (implicit)
 *
 * Upvalues:
 * 1.  pointer to the protocol buffer 
 * 2.  field index 
 *
 * Returns:
 * 1.  true or false if the 'get' was successful
 */
int32_t field_dynamic_getter(lua_State *L)
{
	size_t nbytes;
	lua_packet_segment * array;
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

	int32_t field_index = lua_tointeger(L, lua_upvalueindex(2));
    
	/* the function name is piggybacked as a string */
	lua_getglobal(L, (char *)prot_buf->protocol_fields[field_index].get);
	if (!lua_isfunction(L, -1)) {
		lua_pushboolean(L, 0);
		return 1;
	}

	nbytes = sizeof(lua_packet_segment) + seg->length * sizeof(uint8_t);
	array = (lua_packet_segment *)lua_newuserdata(L, nbytes);
	array->length = seg->length;
	array->start = seg->start + seg->offset;
	array->changes = NULL;

	luaL_getmetatable(L, LUA_BYTE_ARRAY);
	lua_setmetatable(L, -2);
	if (lua_pcall(L, 1, 1, 0) != 0) {
		pr_debug("Error: %s \n", luaL_checkstring(L, -1));
		lua_pop(L, 1);
		lua_pushboolean(L, 0);
	}
	return 1;
}

/* LUA_API: the function 'has_protocol_dynamic' acts as a wrapper around 
 * a given lua has_protocol function of a dynamic protocol buffer. The 
 * string containing the lua function name was piggybacked in the 'has_protocol'
 * member of the protocol_buffer. We call this function passing the actual
 * segment.
 * 
 * Paramters:
 * 1.  lua_packet_segment
 * 2.  protocol type 
 *
 * Returns:
 * 1.  true or false if the payload field contains the given protocol 
 */
int32_t has_protocol_dynamic(lua_State *L, struct protocol_buf * prot_buf, lua_packet_segment * seg, int32_t type)
{
	lua_packet_segment *seg_new;
	int32_t res = 0;                                      
	
    /* the function name is piggybacked as a string */
	lua_getglobal(L, (char *)prot_buf->has_protocol);
	seg_new = (lua_packet_segment *)lua_newuserdata(L, sizeof(lua_packet_segment));
	seg_new->start = seg->start;
	seg_new->offset = seg->offset;
	seg_new->length = seg->length;
	seg_new->changes = NULL;
	luaL_getmetatable(L, prot_buf->name);
	lua_setmetatable(L, -2);
	lua_pushinteger(L, type);  /* push the protocol type */
	if (lua_pcall(L, 2, 1, 0) != 0) {
		pr_debug("Error: %s \n", luaL_checkstring(L, -1));
		lua_pop(L, 1);
		return 0;
	}
	res = lua_toboolean(L, -1);
	lua_pop(L, 1);

	return res;
}

/* LUA_API: the function 'get_field_changes_dynamic' acts as a wrapper around 
 * a given lua get_field_changes function of a dynamic protocol buffer. The 
 * string containing the lua function name was piggybacked in the 'get_field_changes'
 * member of the protocol_buffer. We call this function passing the actual
 * segment. The lua function must return two lua table containing the offset 
 * and length changes (in bits). 
 * 
 * Paramters:
 * 1.  lua_packet_segment 
 *
 * Returns:
 * 1.  new allocated field_changes struct 
 */
struct field_changes * get_field_changes_dynamic(lua_State *L, struct protocol_buf *prot_buf, lua_packet_segment * seg)
{
	lua_packet_segment *seg_new;
	struct field_changes * changes;
	int32_t nr_of_changes, i;

	lua_getglobal(L, (char *)prot_buf->get_field_changes);

	seg_new = (lua_packet_segment *)lua_newuserdata(L, sizeof(lua_packet_segment));
	seg_new->start = seg->start;
	seg_new->offset = seg->offset;
	seg_new->length = seg->length;
	seg_new->changes = NULL;
	luaL_getmetatable(L, prot_buf->name);
	lua_setmetatable(L, -2);

	if (lua_pcall(L, 1, 2, 0) != 0)
		luaL_error(L, "inside get_field_changes_dynamic. %s\n", lua_tostring(L, -1));

	/* the function call must return a table containing length changes */
	luaL_checktype(L, -1, LUA_TTABLE);
	/* the function call must return a table containing offset changes */
	luaL_checktype(L, -2, LUA_TTABLE);
	/* both tables have to be of same size */
	if (lua_objlen(L, -1) != lua_objlen(L, -2))
		luaL_error(L, "the provided tables are not of equal size");

	nr_of_changes = lua_objlen(L, -1);
	changes = get_allocated_field_changes(L, nr_of_changes);

	/* loop over the tables */
	for (i = 1; i < nr_of_changes; i++) {
		lua_rawgeti(L, -1, i);  /* push length value of field at index i */
		changes->field_length_changes[i - 1] = luaL_checkinteger(L, -1);
		lua_pop(L, 1);          /* pop offset value */

		lua_rawgeti(L, -2, i);  /* push offset value of field at index i */
		changes->field_offset_changes[i - 1] = luaL_checkinteger(L, -1);
		lua_pop(L, 1);          /* pop length value */
	}

	/* pop both tables */
	lua_pop(L, 2);

	return changes;
}

/* C_INT: 'get_free_protocol_index' is only used internally. This function
 * gets a free slot inside the array holding all the  protocol buffers.
 * There are several ways to get to this information. In this case I take
 * the way over the reflected array SUPPORTED_PROTOCOL_TABLE inside the
 * Lua state. Since this function is called at laodtime, we do not have
 * to care about performance.
 */
static int32_t get_free_protocol_index(lua_State *L)
{
	int32_t protocol_index;

	lua_getglobal(L, SUPPORTED_PROTOCOL_TABLE);
	protocol_index = lua_objlen(L, -1) + 1;
	lua_pop(L, 1);
	return protocol_index;
}

/* C_API: 'free_dynamic_prot_buf' frees the allocated memory of a given
 * dynamic protocol buffer. this function is normally called inside a 
 * cleanup routine. Be aware, before running this function you must be 
 * sure that no references to the dynamic protocol buffers were available.
 * It's recomended to close the Lua state before calling the function. */
void free_dynamic_prot_buf(struct protocol_buf * prot_buf)
{
	struct protocol_field * field = prot_buf->protocol_fields;

	for (; field->name != NULL; field++) {
		if (field->get) kfree(field->get);
		if (field->set) kfree(field->set);
		if (field->name) kfree((char *)field->name);
	}

	if (prot_buf->payload_field) kfree(prot_buf->payload_field);
	if (prot_buf->has_protocol) kfree(prot_buf->has_protocol);

	if (prot_buf->get_field_changes) kfree(prot_buf->get_field_changes);
	kfree((char *)prot_buf->name);
	kfree(prot_buf);
	return;
}

void cleanup_dynamic_prot_bufs(void)
{
	int32_t i;

	for (i = 0; i < MAX_NR_OF_DYN_PROT_BUFS; i++) {
		if (dyn_prot_buf_array[i]) {
			free_dynamic_prot_buf(dyn_prot_buf_array[i]);
			dyn_prot_buf_array[i] = NULL;
		}
	}
	return;
}


/* C_INT: 'free_protocol_fields' is used internally as a helper function for
 * 'register_dynamic_protbuf'. It is used when durin registration an error
 * occurs and the afore allocated fields needed to be freed. */
static inline void free_protocol_fields(struct protocol_field * prot_fields, int32_t i)
{
	struct protocol_field * f;

	while (i >= 0) {
		f = &prot_fields[i];
		if (f->name) kfree((void *)f->name);
		if (f->get) kfree((void *)f->get);
		if (f->set) kfree((void *)f->set);
		kfree((void *)f);
		i--;
	}
}

/* LUA_API: 'register_dynamic_protbuf' is called from within the Lua script.
 * it takes a Lua table representing the dynamic protocol buffer as parameter.
 * e.g.:
 * 	eth_prot_buf = {
 * 		name = "packet_eth_dyn",
 * 		payload_field = "data",
 * 		protocol_fields = {
 * 			{"dmac", 		0, 		48,		nil,	nil	},
 * 			{"smac", 		48, 	48,		nil,	nil	},
 * 			{"type", 		96, 	16,		nil,	nil	},
 * 			{"data", 		112, 	0,		nil,	nil },
 * 		},
 *		has_protocol = "eth_dyn_has_protocol",
 *		get_field_changes = "eth_dyn_get_field_changes"
 * 	}
 * register_dynamic_protbuf(eth_prot_buf)
 * 
 * the table gets parsed and a new protocol_buf struct is allocated and 
 * initialized using 'register_protbuf', which is also used for the static
 * protocol buffers. This enables an identical behavior like the static
 * protocol buffers. The dynamic protocol buffers are not garbage collected,
 * use 'free_dynamic_protbuf' to free them after closing the Lua state. 
 */
static int32_t register_dynamic_protbuf(lua_State *L)
{
	struct protocol_buf *prot_buf;
	struct protocol_field *field, sentinel = PROT_FIELD_SENTINEL;
	int32_t nr_of_fields, i;

	prot_buf = (struct protocol_buf *)kmalloc(sizeof(struct protocol_buf), GFP_KERNEL);
	prot_buf->is_dynamic = 1;

	/* check if parameter is a table */
	luaL_checktype(L, 1, LUA_TTABLE);

	/* initialize prot_buf.name */
	lua_getfield(L, 1, "name");
	prot_buf->name = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
	strcpy((char *)prot_buf->name, luaL_checkstring(L, -1));
	lua_pop(L, 1);  /* pop res from lua_getfield */

	/* check if protocol buffer is already registered */
	lua_getglobal(L, prot_buf->name);
	if (!lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop res from lua_getglobal */
		pr_debug("protocol_buf '%s' already registered.\n", prot_buf->name);
		goto free_prot_buf;
	}
	lua_pop(L, 1); /* pop res from lua_getglobal */

	/* initialize payload field */
	lua_getfield(L, 1, "payload_field");
	if (lua_isstring(L, -1)) {
		prot_buf->payload_field = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
		strcpy(prot_buf->payload_field, lua_tostring(L, -1));
	}else
		prot_buf->payload_field = NULL;
	lua_pop(L, 1); /* pop res from lua_getfield */

	/* initialize protocol_fields field*/
	lua_getfield(L, 1, "protocol_fields");
	if (!lua_istable(L, -1)) {
		pr_debug("invalid protocol_fields table.\n");
		goto err2;

	}

	nr_of_fields = lua_objlen(L, -1);
	prot_buf->protocol_fields = (struct protocol_field *)kmalloc((nr_of_fields + 1) * sizeof(struct protocol_field), GFP_KERNEL);

	for (i = 1; i <= nr_of_fields; i++) {
		field = &prot_buf->protocol_fields[i - 1];
		/* initialize protocol field */
		lua_rawgeti(L, -1, i);  /* push field-table */
		if (!lua_istable(L, -1)) {
			free_protocol_fields(prot_buf->protocol_fields, i);
			pr_debug("invalid protocol_field at %i.\n", i);
			goto err;
		}

		/* initialize protocol field name */
		lua_rawgeti(L, -1, 1);
		if (!lua_isstring(L, -1)) {
			free_protocol_fields(prot_buf->protocol_fields, i);
			pr_debug("invalid protocol_field name at %i.\n", i);
			goto err;
		}

		field->name = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
		strcpy((char*)field->name, lua_tostring(L, -1));
		lua_pop(L, 1); /* pop field name */

		/* initialize protocol field offset */
		lua_rawgeti(L, -1, 2);
		if (!lua_isnumber(L, -1)) {
			free_protocol_fields(prot_buf->protocol_fields, i);
			pr_debug("invalid protocol_field offset at %i.\n", i);
			goto err;
		}
		field->offset = lua_tointeger(L, -1);
		lua_pop(L, 1); /* pop field offset */

		/* initialize protocol field length */
		lua_rawgeti(L, -1, 3);
		if (!lua_isnumber(L, -1)) {
			free_protocol_fields(prot_buf->protocol_fields, i);
			pr_debug("invalid protocol_field length at %i.\n", i);
			goto err;
		}
		field->length = lua_tointeger(L, -1);
		lua_pop(L, 1); /* pop field length */

		/* initialize protocol field getter */
		lua_rawgeti(L, -1, 4);
		if (lua_isstring(L, -1)) {
			field->get = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
			strcpy((char *)field->get, lua_tostring(L, -1)); /* the get-wrapper knows about the piggybacked string */
		}else
			field->get = NULL;
		lua_pop(L, 1); /* pop field getter */

		/* initialize protocol field setter */
		lua_rawgeti(L, -1, 5);
		if (lua_isstring(L, -1)) {
			field->set = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
			strcpy((char *)field->set, lua_tostring(L, -1)); /* the set-wrapper knows about the piggybacked string */
		}else
			field->set = NULL;
		lua_pop(L, 1); /* pop field setter */

		/* field initialization completed */
		lua_pop(L, 1); /* pop field-table */
	}

	/* put sentinel at the end of protocol_fields */
	memcpy(&prot_buf->protocol_fields[nr_of_fields], &sentinel, sizeof(sentinel));
	lua_pop(L, 1); /* pop protocol-fields-table */

	/* initialize has_protocol field */
	lua_getfield(L, 1, "has_protocol");
	if (lua_isstring(L, -1)) {
		prot_buf->has_protocol = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
		strcpy((char *)prot_buf->has_protocol, lua_tostring(L, -1)); /* the has_protocol-wrapper knows about the piggybacked string */
	}else
		prot_buf->has_protocol = NULL;
	lua_pop(L, 1); /* pop has_protocol */

	/* initialize get_field_changes field */
	lua_getfield(L, 1, "get_field_changes");
	if (lua_isstring(L, -1)) {
		prot_buf->get_field_changes = kmalloc(lua_objlen(L, -1), GFP_KERNEL);
		strcpy((char *)prot_buf->get_field_changes, lua_tostring(L, -1)); /* the get_field_changes-wrapper knows about the piggybacked string */
	}else
		prot_buf->get_field_changes = NULL;
	lua_pop(L, 1);                                                  /* pop get_field_changes */

	/* Storing the pointer to the DYNAMIC protbuf within dyn_prot_buf_array, in order to free it at cleanup */
	for (i = 0; i < MAX_NR_OF_DYN_PROT_BUFS; i++) {
		if (!dyn_prot_buf_array[i]) {
			dyn_prot_buf_array[i] = prot_buf;
			break;
		}else
			goto err;
	}
	
	/* call the "common" register_protbuf */
	register_protbuf(L, prot_buf, get_free_protocol_index(L));      /* register prot_buf as it is done with the static ones */

	return 0;

err:
	kfree(prot_buf->protocol_fields);
err2:
	if (prot_buf->payload_field) kfree(prot_buf->payload_field);
free_prot_buf:
	kfree((void *)prot_buf->name);
	kfree(prot_buf);

	luaL_error(L, "one or more error happend while registering a dynamic protocol buffer, please consult the debug log");

	return 0;

}

void luaopen_protbuf_dynamic(lua_State *L)
{
	lua_getglobal(L, "_G");
	lua_pushcclosure(L, register_dynamic_protbuf, 0);
	lua_setfield(L, -2, "register_dynamic_protbuf");
	lua_pop(L, 1); /* pop _G */
	return;
}
