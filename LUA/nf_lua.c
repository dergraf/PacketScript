#if defined(__KERNEL__)

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/netfilter/x_tables.h>

#endif

#include "lua.h"
#include "lobject.h" /*sizeof(udata) */
#include "lauxlib.h"
#include "controller.h"

#if defined(__KERNEL__) /* reachs until luaopen_nflib */


static int32_t nf_get_random(lua_State *L)
{
	uint32_t  rand = 0;

	get_random_bytes(&rand, sizeof(uint32_t ));
	lua_pushnumber(L, rand);
	return 1;
}

static int32_t nf_get_time(lua_State *L)
{
	lua_pushnumber(L, jiffies_to_msecs(jiffies_64));
	return 1;
}

static const struct luaL_Reg nf_lua_lib_f [] = {
	{ "get_random",	   nf_get_random    },
	{ "get_time",	   nf_get_time	    },
	{ NULL,		   NULL		    }
};

void luaopen_nflib(lua_State *L)
{
	int32_t top;

	luaL_register(L, NETFILTER_LIB, nf_lua_lib_f);
	lua_pop(L, 1);

	/* registering verdicts inside the _G */
	lua_getglobal(L, "_G");
	top = lua_gettop(L);

	lua_pushinteger(L, XT_CONTINUE);
	lua_setfield(L, top, "XT_CONTINUE");    /* continiue with next rule */

	lua_pushinteger(L, NF_DROP);
	lua_setfield(L, top, "NF_DROP");        /* stop traversal in the current table hook and drop packet */

	lua_pushinteger(L, NF_ACCEPT);
	lua_setfield(L, top, "NF_ACCEPT");      /* stop traversal in the current table hook and accept packet */

	lua_pop(L, 1);                          /* pop _G */
}

#endif
