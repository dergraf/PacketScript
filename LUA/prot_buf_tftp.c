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

static const struct protocol_field tftp_protocol_fields[] = {
	/*	 field name    offset  length  getter  setter  */
	{ "opcode",  		0,		16,		get_16_bit_generic,	NULL},
	{ "filename",  		0,		0,		get_string_generic,	NULL},
	{ "mode", 			0,		0,		get_string_generic, NULL},
	{ "block_nr",		0,		16,		get_16_bit_generic, NULL},
	{ "data",			0,		0,		NULL, NULL},
	PROT_FIELD_SENTINEL,
};

struct field_changes * tftp_get_field_changes(lua_State *L, lua_packet_segment * seg)
{
	/* depending on the value stored inside the 'opcode'-field we have to change
	 * offsets and lengths */
	uint8_t *tftp_hdr = seg->start + seg->offset;
	short opcode = ntohs(*((uint16_t *)tftp_hdr));
	/* get an allocated 'field_changes' structure */
	struct field_changes * changes = get_allocated_field_changes(L, 5);
	switch (opcode) {
		case 1:	/* Read Request (RRQ) */
			/* setting offset and length of field 'filename' */
			changes->field_offset_changes[1] = sizeof(unsigned short) << 3;
			changes->field_length_changes[1] = strlen((char *)tftp_hdr + sizeof(unsigned short)) << 3;
			/* setting offset and length of field 'mode' */
			changes->field_offset_changes[2] = changes->field_offset_changes[1] + changes->field_length_changes[1];
			changes->field_length_changes[2] = strlen((char *)tftp_hdr + (changes->field_offset_changes[2] >> 3));
			break;
		case 2:	/* Write Request (WRQ) */
			/* setting offset and length of field 'filename' */
			changes->field_offset_changes[1] = sizeof(unsigned short) << 3;
			changes->field_length_changes[1] = strlen((char *)tftp_hdr + sizeof(unsigned short)) << 3;
			/* setting offset and length of field 'mode' */
			changes->field_offset_changes[2] = changes->field_offset_changes[1] + changes->field_length_changes[1];
			changes->field_length_changes[2] = strlen((char *)tftp_hdr + (changes->field_offset_changes[2] >> 3));
			break;
		case 3:	/* Data (DATA) */
			/* setting offset of field 'block_nr' */
			changes->field_offset_changes[3] = sizeof(unsigned short) << 3;
			/* setting offset of field 'data' */
			changes->field_offset_changes[4] = changes->field_offset_changes[3] + (sizeof(unsigned short) << 3);
			break;
		case 4: /* Acknowledgment (ACK) */
			/* setting offset of field 'block_nr' */
			changes->field_offset_changes[3] = sizeof(unsigned short) << 3;
			break;
		case 5: /* Error (ERROR) */
			/* we don't care ... yet */
			break;
		default:
			break;
	}

	return changes;
}

static const struct protocol_buf tftp_protocol_buf = {
	.is_dynamic			= 0,
	.name				= LUA_PACKET_SEG_TFTP,
	.payload_field		= NULL,
	.protocol_fields	= (struct protocol_field *)&tftp_protocol_fields,
	.has_protocol		= NULL, /* we don't need it, since we don't provide a payload field */
	.get_field_changes	= tftp_get_field_changes,
};

void luaopen_protbuf_tftp(lua_State *L)
{
	register_protbuf(L, (struct protocol_buf *)&tftp_protocol_buf, PACKET_TFTP);
}
