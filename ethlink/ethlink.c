/*
 * ethlink.c	Ethlink tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@mellanox.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/ethlink.h>
#include <libmnl/libmnl.h>
#include <netinet/ether.h>

#include "SNAPSHOT.h"
#include "list.h"
#include "mnlg.h"
#include "json_writer.h"
#include "utils.h"

static int g_new_line_count;

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_out(args...)						\
	do {							\
		if (g_indent_newline) {				\
			fprintf(stdout, "%s", g_indent_str);	\
			g_indent_newline = false;		\
		}						\
		fprintf(stdout, ##args);			\
		g_new_line_count = 0;				\
	} while (0)

#define pr_out_sp(num, args...)					\
	do {							\
		int ret = fprintf(stdout, ##args);		\
		if (ret < num)					\
			fprintf(stdout, "%*s", num - ret, "");	\
		g_new_line_count = 0;				\
	} while (0)

static int g_indent_level;
static bool g_indent_newline;
#define INDENT_STR_STEP 2
#define INDENT_STR_MAXLEN 32
static char g_indent_str[INDENT_STR_MAXLEN + 1] = "";

static void __pr_out_indent_inc(void)
{
	if (g_indent_level + INDENT_STR_STEP > INDENT_STR_MAXLEN)
		return;
	g_indent_level += INDENT_STR_STEP;
	memset(g_indent_str, ' ', sizeof(g_indent_str));
	g_indent_str[g_indent_level] = '\0';
}

static void __pr_out_indent_dec(void)
{
	if (g_indent_level - INDENT_STR_STEP < 0)
		return;
	g_indent_level -= INDENT_STR_STEP;
	g_indent_str[g_indent_level] = '\0';
}

static void __pr_out_newline(void)
{
	if (g_new_line_count < 1) {
		pr_out("\n");
		g_indent_newline = true;
	}
	g_new_line_count++;
}

static int _mnlg_socket_recv_run(struct mnlg_socket *nlg,
				 mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_recv_run(nlg, data_cb, data);
	if (err < 0) {
		if (errno == NULL) {
			pr_err("error parsing attributes\n");
			return -EINVAL;
		} else {
			pr_err("ethlink answers: %s\n", strerror(errno));
			return -errno;
		}
	}
	return 0;
}

static int _mnlg_socket_sndrcv(struct mnlg_socket *nlg,
			       const struct nlmsghdr *nlh,
			       mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_send(nlg, nlh);
	if (err < 0) {
		pr_err("Failed to call mnlg_socket_send\n");
		return -errno;
	}
	return _mnlg_socket_recv_run(nlg, data_cb, data);
}

static int _mnlg_socket_group_add(struct mnlg_socket *nlg,
				  const char *group_name)
{
	int err;

	err = mnlg_socket_group_add(nlg, group_name);
	if (err < 0) {
		pr_err("Failed to call mnlg_socket_group_add\n");
		return -errno;
	}
	return 0;
}

#define DL_OPT_HANDLENAME	BIT(0)

struct el_opts {
	uint32_t present; /* flags of present items */
	char *ifname;
};

struct el {
	struct mnlg_socket *nlg;
	int argc;
	char **argv;
	struct el_opts opts;
	json_writer_t *jw;
	bool json_output;
	bool pretty_output;
	bool verbose;
};

static int el_argc(struct el *el)
{
	return el->argc;
}

static char *el_argv(struct el *el)
{
	if (el_argc(el) == 0)
		return NULL;
	return *el->argv;
}

static void el_arg_inc(struct el *el)
{
	if (el_argc(el) == 0)
		return;
	el->argc--;
	el->argv++;
}

static char *el_argv_next(struct el *el)
{
	char *ret;

	if (el_argc(el) == 0)
		return NULL;

	ret = *el->argv;
	el_arg_inc(el);
	return ret;
}

static char *el_argv_index(struct el *el, unsigned int index)
{
	if (index >= el_argc(el))
		return NULL;
	return el->argv[index];
}

static int strcmpx(const char *str1, const char *str2)
{
	if (strlen(str1) > strlen(str2))
		return -1;
	return strncmp(str1, str2, strlen(str1));
}

static bool el_argv_match(struct el *el, const char *pattern)
{
	if (el_argc(el) == 0)
		return false;
	return strcmpx(el_argv(el), pattern) == 0;
}

static bool el_no_arg(struct el *el)
{
	return el_argc(el) == 0;
}

static const enum mnl_attr_data_type ethlink_policy[ETHLINK_ATTR_MAX + 1] = {
	[ETHLINK_ATTR_IFINDEX] = MNL_TYPE_U32,
	[ETHLINK_ATTR_IFNAME] = MNL_TYPE_NUL_STRING,
};

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, ETHLINK_ATTR_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, ethlink_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int strtouint32_t(const char *str, uint32_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > UINT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtouint16_t(const char *str, uint16_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > USHRT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int el_argv_handle(struct el *el, char **p_ifname, uint32_t *p_handle_bit)
{
	char *str = el_argv_next(el);

	if (!str) {
		pr_err("Device name expected.\n");
		return -EINVAL;
	}
	*p_ifname = str;
	*p_handle_bit = DL_OPT_HANDLENAME;
	return 0;
}

static int el_argv_uint32_t(struct el *el, uint32_t *p_val)
{
	char *str = el_argv_next(el);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint32_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int el_argv_uint16_t(struct el *el, uint16_t *p_val)
{
	char *str = el_argv_next(el);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint16_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int el_argv_str(struct el *el, const char **p_str)
{
	const char *str = el_argv_next(el);

	if (!str) {
		pr_err("String parameter expected\n");
		return -EINVAL;
	}
	*p_str = str;
	return 0;
}

static int el_argv_parse(struct el *el, uint32_t o_required,
			 uint32_t o_optional)
{
	struct el_opts *opts = &el->opts;
	uint32_t o_found = 0;
	int err;

	if (o_required & DL_OPT_HANDLENAME) {
		uint32_t handle_bit;

		err = el_argv_handle(el, &opts->ifname, &handle_bit);
		if (err)
			return err;
		o_found |= handle_bit;
	}

	if (el_argc(el)) {
		pr_err("Unknown option \"%s\"\n", el_argv(el));
		return -EINVAL;
	}

	opts->present = o_found;

	return 0;
}

static void el_opts_put(struct nlmsghdr *nlh, struct el *el)
{
	struct el_opts *opts = &el->opts;

	if (opts->present & DL_OPT_HANDLENAME)
		mnl_attr_put_strz(nlh, ETHLINK_ATTR_IFNAME, opts->ifname);
}

static int el_argv_parse_put(struct nlmsghdr *nlh, struct el *el,
			     uint32_t o_required, uint32_t o_optional)
{
	int err;

	err = el_argv_parse(el, o_required, o_optional);
	if (err)
		return err;
	el_opts_put(nlh, el);
	return 0;
}

static void cmd_dev_help(void)
{
	pr_err("Usage: ethlink dev show [ DEV ]\n");
}

static void pr_out_str(struct el *el, const char *name, const char *val)
{
	if (el->json_output) {
		jsonw_string_field(el->jw, name, val);
	} else {
		if (g_indent_newline)
			pr_out("%s %s", name, val);
		else
			pr_out(" %s %s", name, val);
	}
}

static void pr_out_uint(struct el *el, const char *name, unsigned int val)
{
	if (el->json_output) {
		jsonw_uint_field(el->jw, name, val);
	} else {
		if (g_indent_newline)
			pr_out("%s %u", name, val);
		else
			pr_out(" %s %u", name, val);
	}
}

static void pr_out_u64(struct el *el, const char *name, uint64_t val)
{
	if (val == (uint64_t) -1)
		return pr_out_str(el, name, "unlimited");

	return pr_out_uint(el, name, val);
}

static void pr_out_handle_start(struct el *el, struct nlattr **tb)
{
	const char *ifname;
	uint32_t ifindex;

	ifindex = mnl_attr_get_u32(tb[ETHLINK_ATTR_IFINDEX]);
	ifname = mnl_attr_get_str(tb[ETHLINK_ATTR_IFNAME]);
	if (el->json_output) {
		jsonw_name(el->jw, ifname);
		jsonw_start_object(el->jw);
	} else {
		pr_out("%s:", ifname);
	}
	pr_out_uint(el, "ifindex", ifindex);
}

static void pr_out_handle_end(struct el *el)
{
	if (el->json_output)
		jsonw_end_object(el->jw);
	else
		__pr_out_newline();
}

static void pr_out_handle(struct el *el, struct nlattr **tb)
{
	pr_out_handle_start(el, tb);
	pr_out_handle_end(el);
}

static void pr_out_dev(struct el *el, struct nlattr **tb)
{
	pr_out_handle(el, tb);
}

static void pr_out_section_start(struct el *el, const char *name)
{
	if (el->json_output) {
		jsonw_start_object(el->jw);
		jsonw_name(el->jw, name);
		jsonw_start_object(el->jw);
	}
}

static void pr_out_section_end(struct el *el)
{
	if (el->json_output) {
		jsonw_end_object(el->jw);
		jsonw_end_object(el->jw);
	}
}

static void pr_out_array_start(struct el *el, const char *name)
{
	if (el->json_output) {
		jsonw_name(el->jw, name);
		jsonw_start_array(el->jw);
	} else {
		__pr_out_indent_inc();
		__pr_out_newline();
		pr_out("%s:", name);
		__pr_out_indent_inc();
		__pr_out_newline();
	}
}

static void pr_out_array_end(struct el *el)
{
	if (el->json_output) {
		jsonw_end_array(el->jw);
	} else {
		__pr_out_indent_dec();
		__pr_out_indent_dec();
	}
}

static void pr_out_entry_start(struct el *el)
{
	if (el->json_output)
		jsonw_start_object(el->jw);
}

static void pr_out_entry_end(struct el *el)
{
	if (el->json_output)
		jsonw_end_object(el->jw);
	else
		__pr_out_newline();
}

static int cmd_dev_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct el *el = data;
	struct nlattr *tb[ETHLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[ETHLINK_ATTR_IFINDEX] || !tb[ETHLINK_ATTR_IFNAME])
		return MNL_CB_ERROR;
	pr_out_dev(el, tb);
	return MNL_CB_OK;
}

static int cmd_dev_show(struct el *el)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (el_argc(el) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(el->nlg, ETHLINK_CMD_GET, flags);

	if (el_argc(el) > 0) {
		err = el_argv_parse_put(nlh, el, DL_OPT_HANDLENAME, 0);
		if (err)
			return err;
	}

	pr_out_section_start(el, "dev");
	err = _mnlg_socket_sndrcv(el->nlg, nlh, cmd_dev_show_cb, el);
	pr_out_section_end(el);
	return err;
}

static int cmd_dev(struct el *el)
{
	if (el_argv_match(el, "help")) {
		cmd_dev_help();
		return 0;
	} else if (el_argv_match(el, "show") ||
		   el_argv_match(el, "list") || el_no_arg(el)) {
		el_arg_inc(el);
		return cmd_dev_show(el);
	}
	pr_err("Command \"%s\" not found\n", el_argv(el));
	return -ENOENT;
}

static const char *cmd_name(uint8_t cmd)
{
	switch (cmd) {
	case ETHLINK_CMD_UNSPEC: return "unspec";
	case ETHLINK_CMD_GET: return "get";
	case ETHLINK_CMD_NEW: return "new";
	case ETHLINK_CMD_DEL: return "del";
	default: return "<unknown cmd>";
	}
}

static const char *cmd_obj(uint8_t cmd)
{
	switch (cmd) {
	case ETHLINK_CMD_UNSPEC: return "unspec";
	case ETHLINK_CMD_GET:
	case ETHLINK_CMD_NEW:
	case ETHLINK_CMD_DEL:
		return "dev";
	default: return "<unknown obj>";
	}
}

static void pr_out_mon_header(uint8_t cmd)
{
	pr_out("[%s,%s] ", cmd_obj(cmd), cmd_name(cmd));
}

static bool cmd_filter_check(struct el *el, uint8_t cmd)
{
	const char *obj = cmd_obj(cmd);
	unsigned int index = 0;
	const char *cur_obj;

	if (el_no_arg(el))
		return true;
	while ((cur_obj = el_argv_index(el, index++))) {
		if (strcmp(cur_obj, obj) == 0 || strcmp(cur_obj, "all") == 0)
			return true;
	}
	return false;
}

static int cmd_mon_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct el *el = data;
	struct nlattr *tb[ETHLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	uint8_t cmd = genl->cmd;

	if (!cmd_filter_check(el, cmd))
		return MNL_CB_OK;

	switch (cmd) {
	case ETHLINK_CMD_GET: /* fall through */
	case ETHLINK_CMD_NEW: /* fall through */
	case ETHLINK_CMD_DEL:
		mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
		if (!tb[ETHLINK_ATTR_IFINDEX] || !tb[ETHLINK_ATTR_IFNAME])
			return MNL_CB_ERROR;
		pr_out_mon_header(genl->cmd);
		pr_out_dev(el, tb);
		break;
	}
	return MNL_CB_OK;
}

static int cmd_mon_show(struct el *el)
{
	int err;
	unsigned int index = 0;
	const char *cur_obj;

	while ((cur_obj = el_argv_index(el, index++))) {
		if (strcmp(cur_obj, "all") != 0 &&
		    strcmp(cur_obj, "dev") != 0) {
			pr_err("Unknown object \"%s\"\n", cur_obj);
			return -EINVAL;
		}
	}
	err = _mnlg_socket_group_add(el->nlg, ETHLINK_GENL_MCGRP_CONFIG_NAME);
	if (err)
		return err;
	err = _mnlg_socket_recv_run(el->nlg, cmd_mon_show_cb, el);
	if (err)
		return err;
	return 0;
}

static void cmd_mon_help(void)
{
	pr_err("Usage: ethlink monitor [ all | OBJECT-LIST ]\n"
	       "where  OBJECT-LIST := { dev }\n");
}

static int cmd_mon(struct el *el)
{
	if (el_argv_match(el, "help")) {
		cmd_mon_help();
		return 0;
	} else if (el_no_arg(el)) {
		el_arg_inc(el);
		return cmd_mon_show(el);
	}
	pr_err("Command \"%s\" not found\n", el_argv(el));
	return -ENOENT;
}


static void help(void)
{
	pr_err("Usage: ethlink [ OPTIONS ] OBJECT { COMMAND | help }\n"
	       "       ethlink [ -f[orce] ] -b[atch] filename\n"
	       "where  OBJECT := { dev | monitor }\n"
	       "       OPTIONS := { -V[ersion] | -j[json] | -p[pretty] | -v[verbose] }\n");
}

static int el_cmd(struct el *el, int argc, char **argv)
{
	el->argc = argc;
	el->argv = argv;

	if (el_argv_match(el, "help") || el_no_arg(el)) {
		help();
		return 0;
	} else if (el_argv_match(el, "dev")) {
		el_arg_inc(el);
		return cmd_dev(el);
	} else if (el_argv_match(el, "monitor")) {
		el_arg_inc(el);
		return cmd_mon(el);
	}
	pr_err("Object \"%s\" not found\n", el_argv(el));
	return -ENOENT;
}

static int el_init(struct el *el)
{
	int err;

	el->nlg = mnlg_socket_open(ETHLINK_GENL_NAME, ETHLINK_GENL_VERSION);
	if (!el->nlg) {
		pr_err("Failed to connect to ethlink Netlink\n");
		return -errno;
	}

	if (el->json_output) {
		el->jw = jsonw_new(stdout);
		if (!el->jw) {
			pr_err("Failed to create JSON writer\n");
			goto err_json_new;
		}
		jsonw_pretty(el->jw, el->pretty_output);
	}
	return 0;

err_json_new:
	mnlg_socket_close(el->nlg);
	return err;
}

static void el_fini(struct el *el)
{
	if (el->json_output)
		jsonw_destroy(&el->jw);
	mnlg_socket_close(el->nlg);
}

static struct el *el_alloc(void)
{
	struct el *el;

	el = calloc(1, sizeof(*el));
	if (!el)
		return NULL;
	return el;
}

static void el_free(struct el *el)
{
	free(el);
}

static int el_batch(struct el *el, const char *name, bool force)
{
	char *line = NULL;
	size_t len = 0;
	int ret = EXIT_SUCCESS;

	if (name && strcmp(name, "-") != 0) {
		if (freopen(name, "r", stdin) == NULL) {
			fprintf(stderr,
				"Cannot open file \"%s\" for reading: %s\n",
				name, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	cmdlineno = 0;
	while (getcmdline(&line, &len, stdin) != -1) {
		char *largv[100];
		int largc;

		largc = makeargs(line, largv, 100);
		if (!largc)
			continue;	/* blank line */

		if (el_cmd(el, largc, largv)) {
			fprintf(stderr, "Command failed %s:%d\n",
				name, cmdlineno);
			ret = EXIT_FAILURE;
			if (!force)
				break;
		}
	}

	if (line)
		free(line);

	return ret;
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "Version",		no_argument,		NULL, 'V' },
		{ "force",		no_argument,		NULL, 'f' },
		{ "batch",		required_argument,	NULL, 'b' },
		{ "json",		no_argument,		NULL, 'j' },
		{ "pretty",		no_argument,		NULL, 'p' },
		{ "verbose",		no_argument,		NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	const char *batch_file = NULL;
	bool force = false;
	struct el *el;
	int opt;
	int err;
	int ret;

	el = el_alloc();
	if (!el) {
		pr_err("Failed to allocate memory for ethlink\n");
		return EXIT_FAILURE;
	}

	while ((opt = getopt_long(argc, argv, "Vfb:njpv",
				  long_options, NULL)) >= 0) {

		switch (opt) {
		case 'V':
			printf("ethlink utility, iproute2-ss%s\n", SNAPSHOT);
			ret = EXIT_SUCCESS;
			goto el_free;
		case 'f':
			force = true;
			break;
		case 'b':
			batch_file = optarg;
			break;
		case 'j':
			el->json_output = true;
			break;
		case 'p':
			el->pretty_output = true;
			break;
		case 'v':
			el->verbose = true;
			break;
		default:
			pr_err("Unknown option.\n");
			help();
			ret = EXIT_FAILURE;
			goto el_free;
		}
	}

	argc -= optind;
	argv += optind;

	err = el_init(el);
	if (err) {
		ret = EXIT_FAILURE;
		goto el_free;
	}

	if (batch_file)
		err = el_batch(el, batch_file, force);
	else
		err = el_cmd(el, argc, argv);

	if (err) {
		ret = EXIT_FAILURE;
		goto el_fini;
	}

	ret = EXIT_SUCCESS;

el_fini:
	el_fini(el);
el_free:
	el_free(el);

	return ret;
}
