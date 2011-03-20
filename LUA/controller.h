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

#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include "stdlib.h"     /* wrapper */
#include "string.h"     /* wrapper */
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#if defined(__KERNEL__)
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#endif


/* to compile the stuff in userspace (for testing)*/
#if !defined(__KERNEL__)
#include <stdint.h>
#define pr_debug printf;

#define kmalloc(size, type) malloc(size)
#define kfree(ptr) free(ptr)

#endif


/**********************************************************************/
/* nf Lua configuration                                               */
/**********************************************************************/
#define MAX_NR_OF_PROTOCOLS 16
#define SUPPORTED_PROTOCOL_TABLE "supported_protocols"

#define MAX_NR_OF_FIELDS_IN_DYN_PROT_BUF 32


/**********************************************************************/
/* Static Protocol Buffer configuration                               */
/**********************************************************************/

/* the definitions of the stringified expression of the prot_bufs...
 * make sure all static prot_bufs are listed and are unique */
#define LUA_PACKET_SEG_RAW "packet_raw"
#define LUA_PACKET_SEG_ETH "packet_eth"
#define LUA_PACKET_SEG_ICMP "packet_icmp"
#define LUA_PACKET_SEG_IP "packet_ip"
#define LUA_PACKET_SEG_TCP "packet_tcp"
#define LUA_PACKET_SEG_TCP_OPT "packet_tcp_opt"
#define LUA_PACKET_SEG_UDP "packet_udp"
#define LUA_PACKET_SEG_TFTP "packet_tftp"

/* the enum holding all static prot_bufs... make sure it contains all
 * static prot_bufs */
enum PROT_BUF {
	PACKET_RAW,
	PACKET_ETH,
	PACKET_IP,
	PACKET_ICMP,
	PACKET_TCP,
	PACKET_TCP_OPTIONS,
	PACKET_UDP,
	PACKET_TFTP,
	PACKET_DYNAMIC,
	PACKET_SENTINEL
};

/* the luaopen-function of the prot_bufs... make sure it is called
 * inside luaopen_controller */
void luaopen_protbuf_raw(lua_State *L);
void luaopen_protbuf_eth(lua_State *L);
void luaopen_protbuf_ip(lua_State *L);
void luaopen_protbuf_icmp(lua_State *L);
void luaopen_protbuf_tcp(lua_State *L);
void luaopen_protbuf_tcp_options(lua_State *L);
void luaopen_protbuf_udp(lua_State *L);
void luaopen_protbuf_tftp(lua_State *L);
void luaopen_protbuf_dynamic(lua_State *L);

/**********************************************************************/
/* field changes                                                      */
/**********************************************************************/
struct field_changes {
	int ref_count;
	int *field_length_changes;
	int *field_offset_changes;
};

/**********************************************************************/
/* lua packet segment												  */
/* ------------------                                                 */
/* The struct lua_packet_segment is the integral part of a Lua packet.*/
/* At the very beginning, when a new packet arrives in `lua_tg`_ such */
/* a struct is initialized. The field start then points to the lowest */
/* available header inside the sk_buff structure. During packet       */
/* processing the start pointer remains the same, only the offset and */
/* length value change.                                               */
/**********************************************************************/
#define checkpacketseg(L, i, seg_type) \
	(lua_packet_segment *)luaL_checkudata(L, i, seg_type)

typedef struct lua_packet_segment {
	unsigned int offset;
	unsigned int length;
	struct field_changes * changes;
	unsigned char * start;  /* need to be at the end because of the memory alignment */
} lua_packet_segment;

/**********************************************************************/
/* protocol field                                                     */
/* --------------													  */
/* This structure is a container for the field definitions used by the*/
/* protocol buffer. Each protocol field is expressed using this struct*/
/* Have a look at the protocol buffers to see how the struct gets     */
/* initialized.														  */
/*																	  */
/* name:														      */
/*   This member expresses the name of the field, ending			  */
/*   in its own Lua function to access the field.					  */
/* offset / length:													  */
/*   These members do specify the position inside the protocol header */
/*   in bits (not bytes!).											  */
/* get / set:														  */
/*   The get and set functions take a function pointer pointing to the*/
/*   specific getter and setter function for this field.			  */
/**********************************************************************/
struct protocol_field {
	const char * name;
	uint32_t offset;
	uint32_t length;
	lua_CFunction get;
	lua_CFunction set;
};
#define PROT_FIELD_SENTINEL { NULL, 0, 0, NULL, NULL }


/**********************************************************************/
/* protocol_buf                                                       */
/**********************************************************************/
/* This structure is a container for all the information needed for a
 * protocol buffer. It gets initialized in each protocol buffer header
 * file or for the dynamic protocol buffers on runtime using the
 * 'register_dynamic_protocol_buffer' function.
 *
 * name:
 *   This member is used throughout the system. It is also exported
 *   to Lua as a variable name holding the index of the 'supported_protocols'
 *   array. The name is also used as the name of the generated Lua
 *   metatable, that is why inside the macro checkpacketseg_ it
 *   is always the name of a protocol buffer that is passed as the
 *   second parameter.
 * payload_field:
 *   This member holds the string of the field responsible for payload
 *   data. The payload field of a protocol has an extra property, since
 *   it can be used to invoke another protocol buffer that is applied to
 *   the payload content.
 * has_protocol:
 *   This member is used together with the payload_field. Since we must
 *   be sure that the payload content does really contain a protocol
 *   of type X. The function pointed to by has_protocol checks if the
 *   protocol buffer X can be applied on the payload_data.
 * protocol_fields:
 *   This member points to the array of 'protocol_field' structures
 * get_field_changes:
 *   This member is optional. It is used to return a pointer to an initialized
 *   field_changes struct. The function is called, whenever the payload field
 *   is requested with a given protocol type. Usually this function will
 *   initialize the field_changes struct depending on the content of the 
 *   payload data. e.g.
 *     tcp = ip:data(packet_tcp)
 *   such a request will call the 'get_field_changes' function of the tcp
 *   protocol buffer. This enables, that the tcp options field have the proper
 *   length as well as the tcp data start at the right offset. 
 */
struct protocol_buf {
	int is_dynamic;
	const char * name;
	char * payload_field;
	int (*has_protocol)(lua_State *L, struct protocol_buf *prot_buf, lua_packet_segment * seg, int type);
	struct protocol_field * protocol_fields;
	struct field_changes * (*get_field_changes)(lua_State *L, lua_packet_segment * seg);
};

/**********************************************************************/
/* lua byte array library                                             */
/**********************************************************************/
#define LUA_BYTE_ARRAY "byte_array"
#define checkbytearray(L, i) \
	(lua_packet_segment *)luaL_checkudata(L, i, LUA_BYTE_ARRAY)
lua_packet_segment * init_byte_array(lua_State *L, unsigned char * start, int length, int do_copy);
void luaopen_bytearraylib(lua_State *L);


/**********************************************************************/
/* lua netfilter environment library                                  */
/**********************************************************************/
#define NETFILTER_LIB "nf"
#if defined(__KERNEL__)
	struct lua_env {
		lua_State *L;
		/* perhaps more to come here (e.g. a state per CPU) */
	}; 
	#define LUA_ENV "lua_env"
	#define checkluaenv(L, i) \
	(struct lua_env *)luaL_checkudata(L, i, LUA_ENV)

	void luaopen_nflib(lua_State *L);
#endif

void cleanup_dynamic_prot_bufs(void); /* freeing all dynamic prot bufs */
/**********************************************************************/
/* lua protbuf helpers                                                */
/**********************************************************************/
int get_1_bit_generic(lua_State *L);
int set_1_bit_generic(lua_State *L);
int get_lower_4_bit_generic(lua_State *L);
int set_lower_4_bit_generic(lua_State *L);
int get_upper_4_bit_generic(lua_State *L);
int set_upper_4_bit_generic(lua_State *L);
int get_8_bit_generic(lua_State *L);
int set_8_bit_generic(lua_State *L);
int get_16_bit_generic(lua_State *L);
int set_16_bit_generic(lua_State *L);
int get_32_bit_generic(lua_State *L);
int set_32_bit_generic(lua_State *L);
int set_data_generic(lua_State *L);
int get_string_generic(lua_State *L);
int get_byte_generic_str(lua_State *L);
struct field_changes * get_allocated_field_changes(lua_State *L, int nr_of_fields);

/* only used by the dynamic prot buf subsystem */
#define MAX_NR_OF_DYN_PROT_BUFS 16
int field_dynamic_setter(lua_State *L);
int field_dynamic_getter(lua_State *L);
int has_protocol_dynamic(lua_State *L, struct protocol_buf * prot_buf, lua_packet_segment * seg, int type);
struct field_changes * get_field_changes_dynamic(lua_State *L, struct protocol_buf *prot_buf, lua_packet_segment * seg);

/**********************************************************************/
/* lua controller API                                                 */
/**********************************************************************/
void luaopen_controller(lua_State *L);
struct protocol_buf * get_protocol_buf(unsigned int protocol_id);
void get_metatable_from_protocol_type(lua_State *L, int type);
void register_protbuf(lua_State *L, struct protocol_buf * prot_buf, unsigned int protocol_index);


#endif /* CONTROLLER_H_ */
