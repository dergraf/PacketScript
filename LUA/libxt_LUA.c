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

#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "xt_LUA.h"

enum {
	FLAG_SCRIPT   = 1 << 0,
	FLAG_STATE    = 1 << 1,
	FLAG_FUNCTION = 1 << 2,
};

static const struct option lua_tg_opts[] = {
	{ .name = "script",   .has_arg = true, .val = 's' },
	{ .name = "state",    .has_arg = true, .val = 'l' },
	{ .name = "function", .has_arg = true, .val = 'f' },
	{ NULL },
};


static void lua_tg_help(void)
{
	printf(
		"LUA target options:\n"
		"  --script SCRIPT      Process packet with the Lua script given by SCRIPT\n"
		"                                                                       \n"
		"  --state ID           Process packet within the Lua state given by ID.\n"
		"                       Omitting --state infers the ID 0, which can be\n"
		"                       refered to the 'global' state.\n"
		"                                                                       \n"
		"  --function FUNCTION  Name of the function that processes the Lua packet\n"
		"\n");
}

static void
lua_tg_init(struct xt_entry_target *target)
{
	struct xt_lua_tginfo *info = (void *)target->data;

	info->state_id = 0;
	strncpy(info->function, "process_packet\0", sizeof("process_packet\0"));
}

static int
lua_tg_parse(int32_t c, char **argv, int32_t invert, uint32_t  *flags,
	     const void *entry, struct xt_entry_target **target)
{
	struct xt_lua_tginfo *info = (void *)(*target)->data;
	char buf[MAX_SCRIPT_SIZE];
	long script_size;
	uint32_t  state_id;
	FILE *file;

	switch (c) {
	case 's':
		if (*flags & FLAG_SCRIPT)
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Cannot specify --script more than once");

		if (strlen(optarg) > sizeof(info->filename))
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Maximum script length is %zu",
				      sizeof(info->filename));

		if (strchr(optarg, '\n'))
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Newlines not allowed in script name");
		file = fopen(optarg, "rb");
		if (file != NULL) {
			fseek(file, 0, SEEK_END);
			script_size = ftell(file);
			if (script_size > MAX_SCRIPT_SIZE)
				xtables_error(PARAMETER_PROBLEM,
					      "LUA: The size of the script is too big");

			fseek(file, 0, SEEK_SET);
			fread(buf, script_size, 1, file);
			fclose(file);
		} else
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Cannot open script %s", optarg);

		strncpy(info->filename, optarg, sizeof(info->filename));
		strncpy(info->buf, buf, sizeof(info->buf));
		info->script_size = script_size;

		*flags |= FLAG_SCRIPT;
		return true;

	case 'l':
		if (*flags & FLAG_STATE)
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Cannot specify --state more than once");

		if (!xtables_strtoui(optarg, NULL, &state_id, 0, 8))
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Invalid --state %s", optarg);

		info->state_id = state_id;
		*flags |= FLAG_STATE;
		return true;

	case 'f':
		if (*flags & FLAG_FUNCTION)
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Cannot specify --function more than once");
		if (strlen(optarg) > sizeof(info->function))
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Maximum function length is %zu",
				      sizeof(info->function));

		if (strchr(optarg, '\n'))
			xtables_error(PARAMETER_PROBLEM,
				      "LUA: Newlines not allowed in function name");

		strncpy(info->function, optarg, sizeof(info->function));

		*flags |= FLAG_FUNCTION;
		return true;
	}

	return false;
}

static void
lua_tg_check(uint32_t  flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "LUA: --script parameter required");
}

static void
lua_tg_print(const void *entry, const struct xt_entry_target *target,
	     int32_t numeric)
{
	const struct xt_lua_tginfo *info = (const void *)target->data;

	printf("LUA script: %s ", info->filename);
}

static void
lua_tg_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_lua_tginfo *info = (const void *)target->data;

	printf("--script %s ", info->filename);
}

static struct xtables_target lua_tg_reg = {
	.name			= "LUA",
	.version		= XTABLES_VERSION,
	.revision		= 0,
	.family			= NFPROTO_UNSPEC,
	.size			= XT_ALIGN(sizeof(struct xt_lua_tginfo)),
	.userspacesize		= XT_ALIGN(sizeof(struct xt_lua_tginfo)),
	.help			= lua_tg_help,
	.init			= lua_tg_init,
	.parse			= lua_tg_parse,
	.final_check		= lua_tg_check,
	.print			= lua_tg_print,
	.save			= lua_tg_save,
	.extra_opts		= lua_tg_opts,
};

static __attribute__((constructor)) void lua_tg_ldr(void)
{
	xtables_register_target(&lua_tg_reg);
}

