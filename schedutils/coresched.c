/**
 * SPDX-License-Identifier: EUPL-1.2
 *
 * coresched.c - manage core scheduling cookies for tasks
 *
 * Copyright (C) 2024 Thijs Raymakers
 * Licensed under the EUPL v1.2
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "c.h"
#include "closestream.h"
#include "nls.h"
#include "optutils.h"
#include "strutils.h"

// These definitions might not be defined in the header files, even if the
// prctl interface in the kernel accepts them as valid.
#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE 62
#endif
#ifndef PR_SCHED_CORE_GET
#define PR_SCHED_CORE_GET 0
#endif
#ifndef PR_SCHED_CORE_CREATE
#define PR_SCHED_CORE_CREATE 1
#endif
#ifndef PR_SCHED_CORE_SHARE_TO
#define PR_SCHED_CORE_SHARE_TO 2
#endif
#ifndef PR_SCHED_CORE_SHARE_FROM
#define PR_SCHED_CORE_SHARE_FROM 3
#endif
#ifndef PR_SCHED_CORE_SCOPE_THREAD
#define PR_SCHED_CORE_SCOPE_THREAD 0
#endif
#ifndef PR_SCHED_CORE_SCOPE_THREAD_GROUP
#define PR_SCHED_CORE_SCOPE_THREAD_GROUP 1
#endif
#ifndef PR_SCHED_CORE_SCOPE_PROCESS_GROUP
#define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
#endif

typedef int sched_core_scope;
typedef unsigned long sched_core_cookie;
typedef enum {
	SCHED_CORE_CMD_GET,
	SCHED_CORE_CMD_NEW,
	SCHED_CORE_CMD_COPY,
} sched_core_cmd;

struct args {
	pid_t pid;
	pid_t dest;
	sched_core_scope type;
	sched_core_cmd cmd;
	int exec_argv_offset;
};

static void __attribute__((__noreturn__)) usage(void)
{
	fputs(USAGE_HEADER, stdout);
	fprintf(stdout, _(" %s [-p PID]\n"), program_invocation_short_name);
	fprintf(stdout, _(" %s --new [-t <TYPE>] -p <PID>\n"),
		program_invocation_short_name);
	fprintf(stdout, _(" %s --new [-t <TYPE>] -- PROGRAM [ARGS...]\n"),
		program_invocation_short_name);
	fprintf(stdout, _(" %s --copy -p <PID> [-t <TYPE>] -d <PID>\n"),
		program_invocation_short_name);
	fprintf(stdout,
		_(" %s --copy -p <PID> [-t <TYPE>] -- PROGRAM [ARGS...]\n"),
		program_invocation_short_name);

	fputs(USAGE_SEPARATOR, stdout);
	fputsln(_("Manage core scheduling cookies for tasks."), stdout);

	fputs(USAGE_FUNCTIONS, stdout);
	fputsln(_(" -n, --new          assign a new core scheduling cookie to an existing PID or\n"
		  "                      execute a program with a new cookie."),
		stdout);
	fputsln(_(" -c, --copy         copy the core scheduling cookie from an existing PID to\n"
		  "                      either another PID, or copy it to a new program"),
		stdout);
	fputsln(_("\n If no function is provided, it will retrieve and print the cookie from\n"
		  "   the PID provided via --pid.\n"),
		stdout);

	fputs(USAGE_OPTIONS, stdout);
	fputsln(_(" -p, --pid <PID>    operate on an existing PID"), stdout);
	fputsln(_(" -d, --dest <PID>   when copying a cookie from an existing PID, --dest is\n"
		  "                      the destination PID where to copy the cookie to."),
		stdout);
	fputsln(_(" -t, --type <TYPE>  type of the destination PID, or the type of the PID\n"
		  "                      when a new core scheduling cookie is created.\n"
		  "                      Can be one of the following: pid, tgid or pgid.\n"
		  "                      The default is tgid."),
		stdout);
	fputs(USAGE_SEPARATOR, stdout);
	fprintf(stdout,
		USAGE_HELP_OPTIONS(
			20)); /* char offset to align option descriptions */
	fprintf(stdout, USAGE_MAN_TAIL("coresched(1)"));
	exit(EXIT_SUCCESS);
}

#define bad_usage(FMT...) \
	warnx(FMT);       \
	errtryhelp(EINVAL);

#define check_prctl(FMT...)                                                    \
	if (errno == EINVAL) {                                                 \
		warn(FMT);                                                     \
		errx(errno, _("Does your kernel support CONFIG_SCHED_CORE?")); \
	} else {                                                               \
		err(errno, FMT);                                               \
	}

static sched_core_cookie core_sched_get_cookie(pid_t pid)
{
	sched_core_cookie cookie = 0;
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, pid,
		  PR_SCHED_CORE_SCOPE_THREAD, &cookie)) {
		check_prctl(_("Failed to get cookie from PID %d"), pid);
	}
	return cookie;
}

static void core_sched_create_cookie(pid_t pid, sched_core_scope type)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, pid, type, 0)) {
		check_prctl(_("Failed to create cookie for PID %d"), pid);
	}
}

static void core_sched_pull_cookie(pid_t from)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM, from,
		  PR_SCHED_CORE_SCOPE_THREAD, 0)) {
		check_prctl(_("Failed to pull cookie from PID %d"), from);
	}
}

static void core_sched_push_cookie(pid_t to, sched_core_scope type)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_TO, to, type, 0)) {
		check_prctl(_("Failed to push cookie to PID %d"), to);
	}
}

static void core_sched_copy_cookie(pid_t from, pid_t to,
				   sched_core_scope to_type)
{
	core_sched_pull_cookie(from);
	sched_core_cookie before = core_sched_get_cookie(from);
	core_sched_push_cookie(to, to_type);
	printf(_("%s: copied cookie 0x%lx from PID %d to PID %d\n"),
	       program_invocation_short_name, before, from, to);
}

static void core_sched_get_and_print_cookie(pid_t pid)
{
	sched_core_cookie after = core_sched_get_cookie(pid);
	printf(_("%s: set cookie of PID %d to 0x%lx\n"),
	       program_invocation_short_name, pid, after);
}

static void core_sched_exec_with_cookie(struct args *args, char **argv)
{
	if (!args->exec_argv_offset)
		usage();

	// Move the argument list to the first argument of the program
	argv = &argv[args->exec_argv_offset];

	// If a source PID is provided, try to copy the cookie from
	// that PID. Otherwise, create a brand new cookie with the
	// provided type.
	if (args->pid) {
		core_sched_pull_cookie(args->pid);
		core_sched_get_and_print_cookie(args->pid);
	} else {
		pid_t pid = getpid();
		core_sched_create_cookie(pid, args->type);
		sched_core_cookie after = core_sched_get_cookie(pid);
		printf(_("%s: set cookie of PID %d to 0x%lx\n"),
		       program_invocation_short_name, pid, after);
	}

	if (execvp(argv[0], argv)) {
		errexec(argv[0]);
	}
}

static sched_core_scope parse_core_sched_type(char *str)
{
	if (!strncmp(str, "pid", 4))
		return PR_SCHED_CORE_SCOPE_THREAD;
	else if (!strncmp(str, "tgid", 5))
		return PR_SCHED_CORE_SCOPE_THREAD_GROUP;
	else if (!strncmp(str, "pgid", 5))
		return PR_SCHED_CORE_SCOPE_PROCESS_GROUP;

	bad_usage(_("'%s' is an invalid option. Must be one of pid/tgid/pgid"),
		  str);
}

static void parse_arguments(int argc, char **argv, struct args *args)
{
	int c;

	static const struct option longopts[] = {
		{ "new", no_argument, NULL, 'n' },
		{ "copy", no_argument, NULL, 'c' },
		{ "pid", required_argument, NULL, 'p' },
		{ "dest", required_argument, NULL, 'd' },
		{ "type", required_argument, NULL, 't' },
		{ "version", no_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	static const ul_excl_t excl[] = {
		{ 'c', 'n' }, // Cannot do both --new and --copy
		{ 'd', 'n' }, // Cannot have both --new and --dest
		{ 0 }
	};

	int excl_st[ARRAY_SIZE(excl)] = UL_EXCL_STATUS_INIT;

	while ((c = getopt_long(argc, argv, "ncp:d:t:Vh", longopts, NULL)) !=
	       -1) {
		err_exclusive_options(c, longopts, excl, excl_st);
		switch (c) {
		case 'n':
			args->cmd = SCHED_CORE_CMD_NEW;
			break;
		case 'c':
			args->cmd = SCHED_CORE_CMD_COPY;
			break;
		case 'p':
			args->pid = strtopid_or_err(
				optarg, _("Failed to parse PID for -p/--pid"));
			break;
		case 'd':
			args->dest = strtopid_or_err(
				optarg, _("Failed to parse PID for -d/--dest"));
			break;
		case 't':
			args->type = parse_core_sched_type(optarg);
			break;
		case 'V':
			print_version(EXIT_SUCCESS);
		case 'h':
			usage();
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	if (args->cmd == SCHED_CORE_CMD_COPY && !args->pid) {
		bad_usage(_("--copy: requires a -p/--pid"));
	}

	// More arguments have been passed, which means that the user wants to run
	// another program with a core scheduling cookie.
	if (argc > optind) {
		switch (args->cmd) {
		case SCHED_CORE_CMD_GET:
			bad_usage(_("Unknown command"));
			break;
		case SCHED_CORE_CMD_NEW:
			if (args->pid) {
				bad_usage(_(
					"--new: cannot accept both a -p/--pid and a command"));
			} else {
				args->exec_argv_offset = optind;
			}
			break;
		case SCHED_CORE_CMD_COPY:
			if (args->dest) {
				bad_usage(_(
					"--copy: cannot accept both a destination PID "
					"-d/--dest and a command"))
			} else {
				args->exec_argv_offset = optind;
			}
			break;
		}
	}

	if (argc <= optind) {
		if (args->cmd == SCHED_CORE_CMD_NEW && !args->pid) {
			bad_usage(_(
				"--new: requires either a -p/--pid or a command"));
		}
		if (args->cmd == SCHED_CORE_CMD_COPY && !args->dest) {
			bad_usage(_(
				"--copy: requires either a -d/--dest or a command"));
		}
	}
}

int main(int argc, char **argv)
{
	struct args args = { 0 };
	args.cmd = SCHED_CORE_CMD_GET;
	args.type = PR_SCHED_CORE_SCOPE_THREAD_GROUP;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	parse_arguments(argc, argv, &args);

	sched_core_cookie cookie;

	switch (args.cmd) {
	case SCHED_CORE_CMD_GET:
		if (args.pid) {
			cookie = core_sched_get_cookie(args.pid);
			if (cookie) {
				printf(_("%s: cookie of pid %d is 0x%lx\n"),
				       program_invocation_short_name, args.pid,
				       cookie);
			} else {
				errx(ENODATA,
				     _("pid %d doesn't have a core scheduling cookie"),
				     args.pid);
			}
		} else {
			usage();
		}
		break;
	case SCHED_CORE_CMD_NEW:
		if (args.pid) {
			core_sched_create_cookie(args.pid, args.type);
			core_sched_get_and_print_cookie(args.pid);
		} else {
			core_sched_exec_with_cookie(&args, argv);
		}
		break;
	case SCHED_CORE_CMD_COPY:
		if (args.dest)
			core_sched_copy_cookie(args.pid, args.dest, args.type);
		else
			core_sched_exec_with_cookie(&args, argv);
		break;
	default:
		usage();
	}
}
