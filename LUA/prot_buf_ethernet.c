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


static int32_t eth_has_protocol(lua_State *L, struct protocol_buf * prot_buf, lua_packet_segment * seg, int32_t protocol_type)
{
	uint8_t *embedded_protocol = seg->start + seg->offset + 12 /*bytes*/;
	unsigned short res = (unsigned short)((embedded_protocol[1] << CHAR_BIT) | (embedded_protocol[0] << CHAR_BIT));

	switch (res) {
	case 0x0800:    /* 1: Internet Protocol (IP) */
		if (protocol_type == PACKET_IP) return 1;
		break;
	default:
		return 0;
	}

	return 0;
}

static const struct protocol_field eth_protocol_fields[] = {
	/*	 field name    offset  length  getter  setter  */
	{ "dmac", 0,		      48,	       NULL,		  NULL		    },
	{ "smac", 48,		      48,	       NULL,		  NULL		    },
	{ "type", 96,		      16,	       NULL,		  NULL		    },
	{ "data", 112,		      0,	       NULL,		  NULL		    },
	PROT_FIELD_SENTINEL,
};

static const struct protocol_buf eth_protocol_buf = {
	.is_dynamic			= 0,
	.name				= LUA_PACKET_SEG_ETH,
	.payload_field			= "data",
	.protocol_fields		= (struct protocol_field *)&eth_protocol_fields,
	.has_protocol			= &eth_has_protocol,
	.get_field_changes		= NULL,
};


void luaopen_protbuf_eth(lua_State *L)
{
	register_protbuf(L, (struct protocol_buf *)&eth_protocol_buf, PACKET_ETH);
}
