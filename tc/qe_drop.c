#include "utils.h"
#include "tc_util.h"

static int qe_drop_parse(struct qevent_util *qe, int *p_argc, char ***p_argv,
			 struct nlmsghdr *n)
{
	struct nla_bitfield32 flags_bf = {
		.selector = TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW,
	};
	char **argv = *p_argv;
	int argc = *p_argc;

	while (argc > 0) {
		if (strcmp(*argv, "skip_hw") == 0) {
			NEXT_ARG();
			flags_bf.value |= TCA_CLS_FLAGS_SKIP_HW;
			continue;
		} else if (strcmp(*argv, "skip_sw") == 0) {
			NEXT_ARG();
			flags_bf.value |= TCA_CLS_FLAGS_SKIP_SW;
			continue;
		} else {
			break;
		}
	}

	if (flags_bf.value) {
		// xxx extract to a helper
		if (!(flags_bf.value ^ (TCA_CLS_FLAGS_SKIP_HW |
					TCA_CLS_FLAGS_SKIP_SW))) {
			fprintf(stderr,
				"skip_hw and skip_sw are mutually exclusive\n");
			return -1;
		}
		addattr_l(n, MAX_MSG, TCA_QEVENT_FLAGS,
			  &flags_bf, sizeof(flags_bf));
	}

	*p_argc = argc;
	*p_argv = argv;
	return 0;
}

struct qevent_util drop_qevent_util = {
	.id = "drop",
	.parse_qevent = qe_drop_parse,
};
