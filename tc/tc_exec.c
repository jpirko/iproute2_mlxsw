/*
 * tc_exec.c	"tc exec".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

#include "tc_util.h"
#include "tc_common.h"

static struct exec_util *exec_list;

static void usage(void)
{
	fprintf(stderr,
		"Usage: tc exec [ EXEC_TYPE ] [ help | OPTIONS ]\n"
		"Where:\n"
		"EXEC_TYPE := { bpf | etc. }\n"
		"OPTIONS := ... try tc exec <desired EXEC_KIND> help\n");
}

static int parse_noeopt(struct exec_util *eu, int argc, char **argv)
{
	if (argc) {
		fprintf(stderr, "Unknown exec \"%s\", hence option \"%s\" is unparsable\n",
			eu->id, *argv);
		return -1;
	}

	return 0;
}

static struct exec_util *get_exec_kind(const char *name)
{
	struct exec_util *eu;

	for (eu = exec_list; eu; eu = eu->next)
		if (strcmp(eu->id, name) == 0)
			return eu;

	eu = get_symbol("e", "%s_exec_util", name);
	if (eu == NULL)
		goto noexist;
reg:
	eu->next = exec_list;
	exec_list = eu;

	return eu;
noexist:
	eu = calloc(1, sizeof(*eu));
	if (eu) {
		strncpy(eu->id, name, sizeof(eu->id) - 1);
		eu->parse_eopt = parse_noeopt;
		goto reg;
	}

	return eu;
}

int do_exec(int argc, char **argv)
{
	struct exec_util *eu;
	char kind[FILTER_NAMESZ] = {};

	if (argc < 1) {
		fprintf(stderr, "No command given, try \"tc exec help\".\n");
		return -1;
	}

	if (matches(*argv, "help") == 0) {
		usage();
		return 0;
	}

	strncpy(kind, *argv, sizeof(kind) - 1);

	eu = get_exec_kind(kind);

	argc--;
	argv++;

	return eu->parse_eopt(eu, argc, argv);
}
