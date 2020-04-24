/*
 * tc_qevent.c	"tc qevent".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <memory.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "tc_common.h"
#include "tc_util.h"
#include "utils.h"

static void usage(void)
{
	fprintf(stderr,
		"Usage: tc qevent [ add | del | show ] [dev STRING] [parent CLASSID]\n"
		"                 [QEVENT_TYPE OPTIONS] [action ACTION-SPEC]\n"
		"Where:\n"
		"QEVENT_TYPE := drop\n");
}

static int tc_qevent_modify(int cmd, unsigned int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct tcmsg		t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.t.tcm_family = AF_UNSPEC,
	};
	struct qevent_util *qe = NULL;
	char  d[IFNAMSIZ] = {};
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (d[0])
				duparg("dev", *argv);
			strncpy(d, *argv, sizeof(d)-1);
		} else if (strcmp(*argv, "parent") == 0) {
			__u32 handle;

			NEXT_ARG();
			if (req.t.tcm_parent)
				duparg("parent", *argv);
			if (get_tc_classid(&handle, *argv))
				invarg("Invalid parent ID", *argv);
			req.t.tcm_parent = handle;
		} else if (matches(*argv, "help") == 0) {
			usage();
			return 0;
		} else {
			qe = get_qevent_kind(*argv);
			if (!qe) {
				invarg("Unknown qevent hook", *argv);
				return -1;
			}

			NEXT_ARG_FWD();
			break;
		}

		NEXT_ARG_FWD();
	}

	if (d[0])  {
		ll_init_map(&rth);

		req.t.tcm_ifindex = ll_name_to_index(d);
		if (req.t.tcm_ifindex == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n", d);
			return 1;
		}
	}

	if (!qe) {
		fprintf(stderr, "Qevent hook not specified\n");
		return -1;
	}

	addattr_l(&req.n, sizeof(req), TCA_KIND, qe->id, strlen(qe->id) + 1);

	if (cmd == RTM_NEWQEVENT) {
		tail = addattr_nest(&req.n, MAX_MSG, TCA_OPTIONS|NLA_F_NESTED);
		if (qe->parse_qevent(qe, &argc, &argv, &req.n))
			return 1;
	}

	if (!argc) {
		if (cmd == RTM_NEWQEVENT)
			goto no_act;
	} else if (matches(*argv, "help") == 0) {
		usage();
	} else if (matches(*argv, "action") == 0) {
		if (cmd == RTM_DELQEVENT) {
			fprintf(stderr, "Unexpected \"action\"\n");
			return -1;
		}
		NEXT_ARG();
		if (parse_action(&argc, &argv, TCA_QEVENT_ACT | NLA_F_NESTED,
				 &req.n))
			return -1;
	} else {
	no_act:
		fprintf(stderr, "Expected \"action\"\n");
		return -1;
	}

	if (cmd == RTM_NEWQEVENT)
		addattr_nest_end(&req.n, tail);

	if (rtnl_talk(&rth, &req.n, NULL) < 0) {
		fprintf(stderr, "We have an error talking to the kernel\n");
		return 2;
	}

	return 0;
}

static int tc_qevent_show(int cmd, int argc, char **argv)
{
	fprintf(stderr, "xxx\n");
	return -1;
}

int do_qevent(int argc, char **argv)
{
	if (argc < 1)
		return tc_qevent_show(RTM_GETQEVENT, 0, NULL);
	if (matches(*argv, "add") == 0) {
		return tc_qevent_modify(RTM_NEWQEVENT,
					NLM_F_CREATE | NLM_F_EXCL,
					argc - 1, argv + 1);
	} else if (matches(*argv, "delete") == 0) {
		return tc_qevent_modify(RTM_DELQEVENT, 0,
					argc - 1, argv + 1);
	} else if (matches(*argv, "show") == 0) {
		return tc_qevent_show(RTM_GETQEVENT, argc - 1, argv + 1);
	} else if (matches(*argv, "help") == 0) {
		usage();
		return 0;
	}
	fprintf(stderr, "Command \"%s\" is unknown, try \"tc qevent help\".\n",
		*argv);
	return -1;
}
