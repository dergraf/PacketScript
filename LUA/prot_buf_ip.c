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


#define IP_FMT "%u.%u.%u.%u"
#define IP_ACC(buf) buf[0], buf[1], buf[2], buf[3]


static int32_t ip_version_set(lua_State *L)
{
	uint8_t version_checked;
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *version_seg = seg->start + seg->offset;
	int32_t version = luaL_checkinteger(L, 2);

	luaL_argcheck(L, version >= 0 && version <= 15, 1, "version number invalid");

	version_checked = (uint8_t)version;

	version_seg[0] &= (uint8_t)0x0F;  /* reset version bits */
	version_seg[0] |= version_checked << 4;

	return 0;
}
static int32_t ip_version_get(lua_State *L)
{
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *version_seg = seg->start + seg->offset;
	uint8_t v = version_seg[0] & 0xF0;

	v >>= 4;

	lua_pushinteger(L, v);
	return 1;
}

static int32_t ip_ihl_set(lua_State *L)
{
	uint8_t ihl_checked;
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *ihl_seg = seg->start + seg->offset;
	int32_t ihl = luaL_checkinteger(L, 2);

	luaL_argcheck(L, ihl >= 5 && ihl <= 15, 1, "ip header length invalid");         // RFC 791 5x32 = 160 bits

	ihl_checked = (uint8_t)ihl;

	ihl_seg[0] &= (uint8_t)0xF0;      /* reset ihl bits */
	ihl_seg[0] |= ihl_checked;

	return 0;
}
static int32_t ip_ihl_get(lua_State *L)
{
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *ihl_seg = seg->start + seg->offset;
	uint8_t v = ihl_seg[0] & 0x0F;

	lua_pushinteger(L, v);
	return 1;
}

static int32_t ip_addr_set(lua_State *L)
{
	int32_t field_id = lua_tointeger(L, lua_upvalueindex(2));
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *addr_seg = seg->start + seg->offset;
	uint32_t  old_addr;
	char *ip = (char *)luaL_checkstring(L, 2);
	uint32_t  a, b, c, d;
	struct sk_buff * skb = (struct sk_buff *)lua_touserdata(L, 3);

	/* for tcp / udp checksumming*/
	uint32_t  prot_offset;
	uint8_t *check, *protocol_seg;

	/* end */

	sscanf(ip, IP_FMT, &a, &b, &c, &d);

	luaL_argcheck(L, a < 256 && b < 256 && c < 256 && d < 256, 1, "invalid ip addr");

	old_addr = *((uint32_t  *)addr_seg);
	addr_seg[0] = (uint8_t)a;
	addr_seg[1] = (uint8_t)b;
	addr_seg[2] = (uint8_t)c;
	addr_seg[3] = (uint8_t)d;

#if defined(__KERNEL__)
	if (old_addr != *(uint32_t  *)addr_seg) {
		int32_t offset = (field_id == 10) ? -2 : -6;         /* offset from saddr or daddr */

		csum_replace4((uint16_t *)(addr_seg + offset), old_addr, *(uint32_t  *)addr_seg);

		prot_offset = (field_id == 10) ? -3 : -7;         /* offset from saddr or daddr */
		protocol_seg = seg->start + seg->offset + prot_offset;

		if (skb && (protocol_seg[0] == 0x06 || protocol_seg[0] == 0x11)) {               /* is payload TCP or UDP ? */

			check = seg->start + seg->offset;                       /* tmp res */
			check += (field_id == 10) ? 8 : 16;                     /* the start of the payload, depending saddr or daddr */
			check += (protocol_seg[0] == 0x06) ? 16 : 6;            /* the start of the checksum, depending on TCP or UDP */

			inet_proto_csum_replace4((__sum16 *)check, skb, old_addr, *(uint32_t  *)addr_seg, 1);

			lua_pop(L, 1);
		}
	}
#endif
	return 0;
}





static int32_t ip_addr_get(lua_State *L)
{
	lua_packet_segment * seg = checkpacketseg(L, 1, LUA_PACKET_SEG_IP);
	uint8_t *addr_seg = seg->start + seg->offset;

	char buf[16]; /*max: 255.255.255.255\0 --> 16 chars */

	sprintf(buf, IP_FMT, IP_ACC(addr_seg));
	lua_pushstring(L, buf);
	return 1;
}

static int32_t ip_has_protocol(lua_State *L, struct protocol_buf * prot_buf, lua_packet_segment * seg, int32_t protocol_type)
{
	uint8_t * embedded_protocol = seg->start + seg->offset + 9 /*bytes*/;

	switch (embedded_protocol[0]) {
	case 0x01:      /* 1: Internet Control Message Protocol (ICMP) */
		if (protocol_type == PACKET_ICMP) return 1;
		break;
	case 0x02:      /* 2: Internet Group Management Protocol (IGMP) */
		break;
	case 0x06:      /* 6: Transmission Control Protocol (TCP) */
		if (protocol_type == PACKET_TCP) return 1;
		break;
	case 0x11:      /* 17: User Datagram Protocol (UDP) */
		if (protocol_type == PACKET_UDP) return 1;
		break;
	case 0x59:      /* 89: Open Shortest Path First (OSPF) */
		break;
	case 0x84:      /* 132: Stream Control Transmission Protocol (SCTP) */
		break;
	default:
		break;
	}

	return 0;
}

static const struct protocol_field ip_protocol_fields[] = {
	/*	 field name    offset  length  getter  setter  */
	{ "version",  0,		   4,		   ip_version_get,		   ip_version_set		},
	{ "ihl",      4,		   4,		   ip_ihl_get,			   ip_ihl_set			},
	{ "tos",      8,		   8,		   get_8_bit_generic,		   set_8_bit_generic		},
	{ "tot_len",  16,		   16,		   get_16_bit_generic,		   set_16_bit_generic		},
	{ "id",	      32,		   16,		   get_16_bit_generic,		   set_16_bit_generic		},
	{ "flags",    48,		   3,		   get_1_bit_generic,		   set_1_bit_generic		},
	{ "frag_off", 51,		   13,		   NULL,			   NULL				},
	{ "ttl",      64,		   8,		   get_8_bit_generic,		   set_8_bit_generic		},
	{ "protocol", 72,		   8,		   get_8_bit_generic,		   set_8_bit_generic		},
	{ "check",    80,		   16,		   get_16_bit_generic,		   set_16_bit_generic		},
	{ "saddr",    96,		   32,		   ip_addr_get,			   ip_addr_set			},
	{ "daddr",    128,		   32,		   ip_addr_get,			   ip_addr_set			},
	{ "data",     160,		   0,		   NULL,			   set_data_generic		},
	PROT_FIELD_SENTINEL,
};

static const struct protocol_buf ip_protocol_buf = {
	.is_dynamic			= 0,
	.name				= LUA_PACKET_SEG_IP,
	.payload_field			= "data",
	.protocol_fields		= (struct protocol_field *)&ip_protocol_fields,
	.has_protocol			= &ip_has_protocol,
	.get_field_changes		= NULL,
};

void luaopen_protbuf_ip(lua_State *L)
{
	register_protbuf(L, (struct protocol_buf *)&ip_protocol_buf, PACKET_IP);
}

