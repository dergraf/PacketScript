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

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include "xt_LUA.h"

#include "controller.h"

/*::*
 * lua_envs
 * ----------
 * This array holds a defined number of `lua_envs`_ structures.
 * The used array index is also used as the Lua state identifier.
 * The size of the array is defined in `LUA_STATE_ARRAY_SIZE`_.
 */
struct lua_env * lua_envs[LUA_STATE_ARRAY_SIZE];

/*::*
 * lua_state_refs
 * --------------
 * This array holds the reference counts of the several `lua_nf_state`_s
 * which are stored inside the array `lua_states`_.
 */
uint32_t  lua_state_refs[LUA_STATE_ARRAY_SIZE] = { 0 };

/*::*
 * lua_tg
 * ------
 * This function is called whenever a packet matches all matching conditions
 * inside a rule. It is the target. It extracts the state identifier comming
 * inside the *xt_target_param* structure and uses it to access the proper
 * Lua state inside the `lua_states`_ array.
 *
 * It then constructs a new Lua userdata of type *lua_packet_segment* and
 * initializes it with the lowest network header available. This userdata
 * is annotated with the Lua metatable `LUA_PACKET_SEG_RAW`_ which converts
 * the userdata to a raw lua packet having all raw functions available.
 * This raw packet is the single parameter to the Lua function *process_packet*
 * which must be defined inside the Lua script provided by the user. So far
 * hardcoded, may be later configured by Lua - subject to change.
 *
 * The process_packet function must return an integer value, the verdict. For
 * convenience reasons xt_LUA exports the verdicts NF_ACCEPT, NF_DROP and
 * XT_CONTINUE inside the *register_lua_packet_lib* function.
 */

spinlock_t lock = SPIN_LOCK_UNLOCKED;

static uint32_t 
lua_tg(struct sk_buff *pskb, const struct xt_target_param *par)
{
	uint32_t  verdict;
	lua_packet_segment *p;
	const struct xt_lua_tginfo *info = par->targinfo;
	lua_State * L;

	/* START critical section on SMP, PacketScript is on the sequential trail at the moment TODO*/
	spin_lock_irq(&lock);

	L = lua_envs[info->state_id]->L;

	if (!skb_make_writable(pskb, pskb->len))
		return NF_DROP;

	/* call the function provided by --function parameter or the default 'process_packet' defined in Lua */
	lua_getglobal(L, info->function);

	/* push the lua_packet_segment as a parameter */
	p = (lua_packet_segment *)lua_newuserdata(L, sizeof(lua_packet_segment));
	if (pskb->mac_header)
		p->start = pskb->mac_header;
	else if (pskb->network_header)
		p->start = pskb->network_header;
	else if (pskb->transport_header)
		p->start = pskb->transport_header;
	p->offset = 0;
	p->length = pskb->tail - p->start;
	p->changes = NULL;

	/* marking userdata 'lua_packet_seg' with the corresponding metatable */
	luaL_getmetatable(L, LUA_PACKET_SEG_RAW);
	lua_setmetatable(L, -2);

	/* push a reference to the skb as a parameter, needed at the moment for calculating TCP checksum, but I am not happy with it*/
	lua_pushlightuserdata(L, (void *)skb_get(pskb));

	/* do the function call (2 argument, 1 result) */
	if (lua_pcall(L, 2, 1, 0) != 0) {
		printk(KERN_ERR "LUA [%d]: pcall '%s' failed: %s\n", info->state_id, info->function, lua_tostring(L, -1));
		lua_pop(L, 1);
		return NF_DROP;
	}

	if (!lua_isnumber(L, -1)) {
		printk(KERN_ERR "LUA [%d]: function '%s' must return a verdict\n", info->state_id, info->function);
		lua_pop(L, 1);
		return NF_DROP;
	}

	verdict = lua_tonumber(L, -1);
	lua_pop(L, 1);

	kfree_skb(pskb);

	/* END critical section on SMP */
	spin_unlock_irq(&lock);


	return verdict;

} 
/* Helper for checkentry */
static bool load_script_into_state(uint32_t  state_id, unsigned long script_size, char *script_buf)
{
	char *buf = kmalloc(script_size, GFP_KERNEL);
	int32_t ret;
	struct lua_env * env = kmalloc(sizeof(struct lua_env), GFP_KERNEL);

	if (!script_size > 0) {
		pr_debug("LUA [%d]: script_size %lu < 0\n", state_id, script_size);
		return false;
	}

	env->L = lua_open();
	luaopen_base(env->L);
	luaopen_controller(env->L);

	lua_getglobal(env->L, "_G");
	lua_pushinteger(env->L, state_id);
	lua_setfield(env->L, -2, "STATE_ID");
	lua_pop(env->L, 1); /* pop _G */

	strncpy(buf, script_buf, script_size);
	ret = luaL_loadbuffer(env->L, buf, script_size, "PacketScript, loadbuffer") ||
	      lua_pcall(env->L, 0, 1, 0);

	if (ret != 0) {
		printk(KERN_ERR "LUA [%d]: failure loading script, error %s \n", state_id, lua_tostring(env->L, -1));
		lua_pop(env->L, 1);
		kfree(buf);
		kfree(env);
		return false;
	}

	lua_envs[state_id] = env;

	kfree(buf);

	return true;
}
/*::*
 * lua_tg_checkentry
 * -----------------
 * This function is used as a kernel-side sanity check of the data comming
 * from the iptables userspace program. Since this is the function which is
 * called everytime a new rule (with -j xt_LUA) is injected, this function
 * is used to do the bookkeeping work, such as counting the reference of
 * several Lua states and the initialization of new states if needed. As an
 * extra initialization step it loads the provided Lua script into the Lua
 * state.
 *
 * Lua state initialization
 * ~~~~~~~~~~~~~~~~~~~~~~~~
 * 1. If a new rule is inserted and there is no existing state for the given
 *    state identifier (default state identifier is 0) a new Lua state is
 *    initialized using *lua_open*.
 * 2. The Lua base library is registered inside the newly initialized state.
 *    Have a look at *lua/lbaselib.c* to see what functions of the Lua base
 *    library are available inside Lua.
 * 3. The Lua packet library is registered inside the Lua state using the
 *    function *register_lua_packet_lib*. So far this function only registers
 *    the Netfilter verdicts NF_ACCEPT, NF_DROP and XT_CONTINUE inside the
 *    global environment of the given Lua state.
 * 4. All the protocol Buffers, and the functions for accessing the bytes are
 *    registered using *register_protocols*.
 *
 * Lua state reference counting
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Bookkeeping of the Lua states inside the *lua_state_refs* array. The
 * state identifier is mapped to the array index, which holds an integer
 * counting the several initialized states.
 *
 * Loading the Lua script
 * ~~~~~~~~~~~~~~~~~~~~~~
 * Copying the buffer which was initialized by the userspace program to a
 * buffer with the proper size. The script is then loaded by the function
 * xt_LUA_loadcode, which wrapps the *luaL_loadbuffer* function and does
 * some workqueue initialization. So far this is done each time this function
 * is called, subject to change.
 */
static bool
lua_tg_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_lua_tginfo *info = par->targinfo;

	if (load_script_into_state(info->state_id, info->script_size, (char *)info->buf)) {
		lua_state_refs[info->state_id]++;
		return true;
	}
	return false;
}

/*::*
 * lua_tg_destroy
 * --------------
 * This function is the counterpart of the `lua_tg_checkentry`_ function. It is
 * responsible to free all the resources alocated inside the checkentry process.
 * To be more specific it frees the Lua state using *lua_close* and kfree on all
 * the dynamically allocated pointers to the registered dynamic protocol buffers.
 *
 * Additionally the function cares about decrementing the reference counters
 * inside the array `lua_states`_.
 */
static void
lua_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_lua_tginfo *info = par->targinfo;
	struct lua_env * env = lua_envs[info->state_id];

	if (lua_state_refs[info->state_id] == 1) {
		lua_close(env->L);
		cleanup_dynamic_prot_bufs();  /* clean memory allocated by protocols defined in Lua */
		kfree(env);
		pr_debug("LUA [%d]: Rule removed, close Lua state\n", info->state_id);
	} else
		pr_debug("LUA [%d]: Rule removed, Lua state stays open, referenced %d time(s)\n",
			 info->state_id, lua_state_refs[info->state_id] - 1);
	
	lua_state_refs[info->state_id]--;
}

static struct xt_target lua_tg_reg __read_mostly = {
	.name			= "LUA",
	.revision		= 0,
	.family			= NFPROTO_UNSPEC,
	.targetsize		= XT_ALIGN(sizeof(struct xt_lua_tginfo)),
	.target			= lua_tg,
	.checkentry		= lua_tg_checkentry,
	.destroy		= lua_tg_destroy,
	.me			= THIS_MODULE,
};


static int32_t lua_tg_init(void)
{
	return xt_register_target(&lua_tg_reg);
}

static void lua_tg_exit(void)
{
	xt_unregister_target(&lua_tg_reg);
}

module_init(lua_tg_init);
module_exit(lua_tg_exit);

MODULE_AUTHOR("Andre Graf <andre@dergraf.org>");
MODULE_DESCRIPTION("Xtables: Processing of matched packets using the Lua scripting environment");
MODULE_ALIAS("ipt_LUA");
MODULE_ALIAS("ipt6t_LUA");
MODULE_ALIAS("arpt_LUA");
MODULE_ALIAS("ebt_LUA");
MODULE_LICENSE("GPL");



