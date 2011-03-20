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
	#include <net/checksum.h>
	#include <net/tcp.h>
#endif
#include "controller.h"


static int32_t tcp_has_protocol(lua_State *L, struct protocol_buf * prot_buf, lua_packet_segment * seg, int32_t protocol_type)
{
	return 1;
}

static int32_t tcp_set_checksum(lua_State *L)
{
	struct protocol_buf * prot_buf = (struct protocol_buf *)lua_topointer(L, lua_upvalueindex(1));
	lua_packet_segment * seg = checkpacketseg(L, 1, prot_buf->name);

#if defined(__KERNEL__)
	uint8_t * check_seg = seg->start + seg->offset;
	uint8_t * tcp_hdr = check_seg - 16;
	uint8_t * saddr = tcp_hdr - 8;
	uint8_t * daddr = saddr + 4;
	uint32_t  len = 20 + (seg->changes->field_length_changes[11] / 8) + (seg->changes->field_length_changes[10] / 8);
	unsigned short checksum = tcp_v4_check(len, *(uint32_t  *)saddr, *(uint32_t  *)daddr,
					       csum_partial(tcp_hdr, len, 0));

	memcpy(check_seg, &checksum, sizeof(unsigned short));
#endif
	return 0;
}


static const struct protocol_field tcp_protocol_fields[] = {
	/*	 field name    offset  length  getter  setter  */
	{ "sport",	 0,			     16,	      get_16_bit_generic,		    set_16_bit_generic		   },
	{ "dport",	 16,			     16,	      get_16_bit_generic,		    set_16_bit_generic		   },
	{ "seq",	 32,			     32,	      get_32_bit_generic,		    set_32_bit_generic		   },
	{ "ack",	 64,			     32,	      get_32_bit_generic,		    set_32_bit_generic		   },
	{ "data_off",	 96,			     4,		      get_lower_4_bit_generic,		    set_lower_4_bit_generic	   },
	{ "reserved",	 100,			     4,		      get_upper_4_bit_generic,		    set_upper_4_bit_generic	   },
	{ "flags",	 104,			     8,		      get_1_bit_generic,		    set_1_bit_generic		   },
	{ "window_size", 112,			     16,	      get_16_bit_generic,		    set_16_bit_generic		   },
	{ "check",	 128,			     16,	      get_16_bit_generic,		    tcp_set_checksum		   },
	{ "urgent",	 144,			     16,	      NULL,				    NULL			   },
	{ "options",	 160,			     0,		      NULL,				    set_data_generic		   },
	{ "data",	 160,			     0,		      NULL,				    set_data_generic		   }, /* begin of data depends on options */
	PROT_FIELD_SENTINEL,
};


static const struct protocol_field tcp_options_and_data[] = {
	/*	 field name    offset  length  getter  setter  */
	{ "MSS",   0,			       16,		get_16_bit_generic,		set_16_bit_generic	     },
	{ "WS",	   0,			       8,		get_8_bit_generic,		set_8_bit_generic	     },
	{ "SACK",  0,			       16,		get_16_bit_generic,		set_16_bit_generic	     },
	{ "TSVAL", 0,			       32,		get_32_bit_generic,		set_32_bit_generic	     },
	{ "TSER",  0,			       32,		get_32_bit_generic,		set_32_bit_generic	     },
	PROT_FIELD_SENTINEL,
};


static struct field_changes * tcp_get_field_changes(lua_State *L, lua_packet_segment * seg);

static const struct protocol_buf tcp_protocol_buf = {
	.is_dynamic			= 0,
	.name				= LUA_PACKET_SEG_TCP,
	.payload_field			= "data",
	.protocol_fields		= (struct protocol_field *)&tcp_protocol_fields,
	.has_protocol			= &tcp_has_protocol,
	.get_field_changes		= &tcp_get_field_changes,
};


static struct field_changes * tcp_options_get_field_changes(lua_State *L, lua_packet_segment * seg);

static const struct protocol_buf tcp_options_and_data_buf = {
	.is_dynamic			= 0,
	.name				= LUA_PACKET_SEG_TCP_OPT,
	.payload_field			= NULL,
	.protocol_fields		= (struct protocol_field *)&tcp_options_and_data,
	.has_protocol			= NULL,
	.get_field_changes		= &tcp_options_get_field_changes,
};

struct field_changes * tcp_get_field_changes(lua_State *L, lua_packet_segment * seg)
{
	/* depending on the value stored inside the 'data_off'-field, the length of
	 * the 'options' field has to be changed, as well as the length and offset
	 * of the 'data' field */
	uint8_t *tcp_hdr = seg->start + seg->offset;

	/* get the pointer to the 'data_off' field */
	uint8_t * data_off_field = tcp_hdr + 12; /* 12 bytes offset */
	/* extract the stored header length in bits */
	uint32_t  tcp_hdr_len = ((*(uint8_t *)data_off_field) >> 4) * 32;

	/* get an allocated 'field_changes' structure */
	struct field_changes * changes = get_allocated_field_changes(L, 12);

	/* depending on the tcp header length, change the length of the options*/
	changes->field_length_changes[10] = tcp_hdr_len - 160;
	/* depending on the options length, change the offset of the data */
	changes->field_offset_changes[11] = changes->field_length_changes[10];
	changes->field_length_changes[11] = (seg->length * 8) - tcp_hdr_len;

	return changes;

}

struct field_changes * tcp_options_get_field_changes(lua_State *L, lua_packet_segment * seg)
{
	/* depending on the value stored inside the 'data_off'-field, the length of
	 * the 'options' field has to be changed, as well as the length and offset
	 * of the 'data' field */
	uint8_t *tcp_opt_hdr = seg->start + seg->offset;

	/* get an allocated 'field_changes' structure */
	struct field_changes * changes = get_allocated_field_changes(L, 5);

	int32_t MSS = 0, WS = 0, SACK = 0, TS = 0, i;

	uint8_t b1, b2;

	for (i = 0; i < seg->length; i++) {
		b1 = tcp_opt_hdr[i];
		b2 = tcp_opt_hdr[i + 1];

		if (b1 == 0x00)
			break;

		/* test for MSS */
		if (!MSS && (b1 == 0x02 && b2 == 0x04)) {
			changes->field_offset_changes[0] = (i + 2) * CHAR_BIT;
			MSS = 1;
		}

		/* test for WS --- yet buggy somehow */
		if (!WS && (b1 == 0x03 && b2 == 0x03)) {
			changes->field_offset_changes[1] = (i + 2) * CHAR_BIT;
			WS = 1;
		}

		/* test for SACK*/
		if (!SACK && (b1 == 0x04 && b2 == 0x02)) {
			changes->field_offset_changes[2] = i * CHAR_BIT;        /* has no value */
			SACK = 1;
		}

		/* test for TS */
		if (!TS && (b1 == 0x08 && b2 == 0x0A)) {
			changes->field_offset_changes[3] = (i + 2) * CHAR_BIT;
			changes->field_offset_changes[4] = (i + 2 + 4) * CHAR_BIT;
			TS = 1;
		}
	}

	return changes;

}

void luaopen_protbuf_tcp(lua_State *L)
{
	register_protbuf(L, (struct protocol_buf *)&tcp_protocol_buf, PACKET_TCP);
}
void luaopen_protbuf_tcp_options(lua_State *L)
{
	register_protbuf(L, (struct protocol_buf *)&tcp_options_and_data_buf, PACKET_TCP_OPTIONS);
}


