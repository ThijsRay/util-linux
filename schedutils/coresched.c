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

#include "c.h"
#include "closestream.h"
#include "nls.h"
#include "strutils.h"

// These definitions might not be defined, even if the
// prctl interface accepts them.
#ifndef PR_SCHED_CORE_SCOPE_THREAD
#define PR_SCHED_CORE_SCOPE_THREAD 0
#endif
#ifndef PR_SCHED_CORE_SCOPE_THREAD_GROUP
#define PR_SCHED_CORE_SCOPE_THREAD_GROUP 1
#endif
#ifndef PR_SCHED_CORE_SCOPE_PROCESS_GROUP
#define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
#endif

typedef int core_sched_type_t;
typedef enum {
	SCHED_CORE_CMD_EXEC = 0,
	SCHED_CORE_CMD_GET = 1,
	SCHED_CORE_CMD_CREATE = 2,
	SCHED_CORE_CMD_COPY = 4,
} core_sched_cmd_t;

struct args {
	pid_t from_pid;
	pid_t to_pid;
	core_sched_type_t type;
	core_sched_cmd_t cmd;
	int exec_argv_offset;
};

unsigned long core_sched_get_cookie(struct args *args);
void core_sched_create_cookie(struct args *args);
void core_sched_pull_cookie(pid_t from);
void core_sched_push_cookie(pid_t to, core_sched_type_t type);
void core_sched_copy_cookie(struct args *args);
void core_sched_exec_with_cookie(struct args *args, char **argv);

core_sched_type_t parse_core_sched_type(char *str);
bool verify_arguments(struct args *args);
void parse_arguments(int argc, char **argv, struct args *args);
void set_pid_or_err(pid_t *dest, pid_t src, const char *err_msg);
static void __attribute__((__noreturn__)) usage(void);

unsigned long core_sched_get_cookie(struct args *args)
{
	unsigned long cookie = 0;
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, args->from_pid,
		  PR_SCHED_CORE_SCOPE_THREAD, &cookie)) {
		err(errno, "Failed to get cookie from PID %d", args->from_pid);
	}
	return cookie;
}

void core_sched_create_cookie(struct args *args)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, args->to_pid, args->type,
		  0)) {
		err(errno, "Failed to create cookie for PID %d",
		    args->from_pid);
	}
}

void core_sched_pull_cookie(pid_t from)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM, from,
		  PR_SCHED_CORE_SCOPE_THREAD, 0)) {
		err(errno, "Failed to pull cookie from PID %d", from);
	}
}

void core_sched_push_cookie(pid_t to, core_sched_type_t type)
{
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_TO, to, type, 0)) {
		err(errno, "Failed to push cookie to PID %d", to);
	}
}

void core_sched_copy_cookie(struct args *args)
{
	core_sched_pull_cookie(args->from_pid);
	core_sched_push_cookie(args->to_pid, args->type);
}

void core_sched_exec_with_cookie(struct args *args, char **argv)
{
	if (!args->exec_argv_offset) {
		usage();
	}

	// Move the argument list to the first argument of the program
	argv = &argv[args->exec_argv_offset];

	// If a source PID is provided, try to copy the cookie from
	// that PID. Otherwise, create a brand new cookie with the
	// provided type.
	if (args->from_pid) {
		core_sched_pull_cookie(args->from_pid);
	} else {
		args->to_pid = getpid();
		core_sched_create_cookie(args);
	}

	if (execvp(argv[0], argv)) {
		errexec(argv[0]);
	}
}

core_sched_type_t parse_core_sched_type(char *str)
{
	if (!strncmp(str, "pid\0", 4)) {
		return PR_SCHED_CORE_SCOPE_THREAD;
	} else if (!strncmp(str, "tgid\0", 5)) {
		return PR_SCHED_CORE_SCOPE_THREAD_GROUP;
	} else if (!strncmp(str, "pgid\0", 5)) {
		return PR_SCHED_CORE_SCOPE_PROCESS_GROUP;
	}

	errx(EINVAL, "'%s' is an invalid option. Must be one of pid/tgid/pgid",
	     str);
	__builtin_unreachable();
}

static void __attribute__((__noreturn__)) usage(void)
{
	fputs(USAGE_HEADER, stdout);
	fprintf(stdout, _(" %s --get <PID>\n"), program_invocation_short_name);
	fprintf(stdout, _(" %s --new <PID> [-t <TYPE>]\n"),
		program_invocation_short_name);
	fprintf(stdout, _(" %s --copy -s <PID> -d <PID> [-t <TYPE>]\n"),
		program_invocation_short_name);
	fprintf(stdout, _(" %s [-s <PID>] -- PROGRAM ARGS... \n"),
		program_invocation_short_name);

	fputs(USAGE_SEPARATOR, stdout);
	fputsln(_("Manage core scheduling cookies for tasks."), stdout);

	fputs(USAGE_FUNCTIONS, stdout);
	fputsln(_(" -g, --get <PID>         get the core scheduling cookie of a PID"),
		stdout);
	fputsln(_(" -n, --new <PID>         assign a new core scheduling cookie to PID"),
		stdout);
	fputsln(_(" -c, --copy              copy the core scheduling cookie from PID to\n"
		  "                           another PID, requires the --source and --dest option"),
		stdout);

	fputs(USAGE_OPTIONS, stdout);
	fputsln(_(" -s, --source <PID>      where to copy the core scheduling cookie from."),
		stdout);
	fputsln(_(" -d, --dest <PID>        where to copy the core scheduling cookie to."),
		stdout);
	fputsln(_(" -t, --type              type of the destination PID, or the type of\n"
		  "                           the PID when a new core scheduling cookie\n"
		  "                           is created. Can be one of the following:\n"
		  "                           pid, tgid or pgid. Defaults to tgid."),
		stdout);
	fputs(USAGE_SEPARATOR, stdout);
	fprintf(stdout,
		USAGE_HELP_OPTIONS(
			25)); /* char offset to align option descriptions */
	fprintf(stdout, USAGE_MAN_TAIL("coresched(1)"));
	exit(EXIT_SUCCESS);
}

bool verify_arguments(struct args *args)
{
	// Check if the value of args->cmd is a power of 2
	// In that case, only a single function option was set.
	if (args->cmd & (args->cmd - 1)) {
		errx(EINVAL,
		     "Cannot do more than one function at a time. See %s --help",
		     program_invocation_short_name);
	}

	switch (args->cmd) {
	case SCHED_CORE_CMD_GET:
		if (args->to_pid) {
			errx(EINVAL,
			     "Cannot use -d/--dest with this -g/--get. See %s --help",
			     program_invocation_short_name);
		}
		break;
	case SCHED_CORE_CMD_CREATE:
		if (args->from_pid) {
			errx(EINVAL,
			     "Cannot use -s/--source with this -n/--new. See %s --help",
			     program_invocation_short_name);
		}
		break;
	case SCHED_CORE_CMD_COPY:
		if (!args->from_pid) {
			errx(EINVAL,
			     "-s/--source PID is required when copying");
		}
		if (!args->to_pid) {
			errx(EINVAL, "-d/--dest PID is required when copying");
		}
		break;
	case SCHED_CORE_CMD_EXEC:
		if (args->to_pid) {
			errx(EINVAL,
			     "Cannot use -d/--dest when spawning a program. See %s --help",
			     program_invocation_short_name);
		}
		break;
	}
	return true;
}

void set_pid_or_err(pid_t *dest, pid_t src, const char *err_msg)
{
	if (*dest) {
		errx(EINVAL, "Ambigious usage: %s", err_msg);
	} else {
		*dest = src;
	}
}

static const char *ERR_MSG_MULTIPLE_SOURCE_PIDS =
	"Multiple source PIDs defined";
void parse_arguments(int argc, char **argv, struct args *args)
{
	int c;
	pid_t tmp;

	static const struct option longopts[] = {
		{ "get", required_argument, NULL, 'g' },
		{ "new", required_argument, NULL, 'n' },
		{ "copy", no_argument, NULL, 'c' },
		{ "source", required_argument, NULL, 's' },
		{ "destination", required_argument, NULL, 'd' },
		{ "type", required_argument, NULL, 't' },
		{ "version", no_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "g:n:cs:d:t:Vh", longopts, NULL)) !=
	       -1)
		switch (c) {
		case 'g':
			args->cmd |= SCHED_CORE_CMD_GET;
			tmp = strtopid_or_err(
				optarg, "Failed to parse PID for -g/--get");
			set_pid_or_err(&args->from_pid, tmp,
				       ERR_MSG_MULTIPLE_SOURCE_PIDS);
			break;
		case 'n':
			args->cmd |= SCHED_CORE_CMD_CREATE;
			tmp = strtopid_or_err(
				optarg, "Failed to parse PID for -n/--new");
			set_pid_or_err(&args->to_pid, tmp,
				       ERR_MSG_MULTIPLE_SOURCE_PIDS);
			break;
		case 'c':
			args->cmd |= SCHED_CORE_CMD_COPY;
			break;
		case 's':
			tmp = strtopid_or_err(
				optarg, "Failed to parse PID for -s/--source");
			set_pid_or_err(&args->from_pid, tmp,
				       ERR_MSG_MULTIPLE_SOURCE_PIDS);
			break;
		case 'd':
			tmp = strtopid_or_err(
				optarg, "Failed to parse PID for -d/--dest");
			set_pid_or_err(&args->to_pid, tmp,
				       "Multiple destination PIDs defined");
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

	if (argc > optind) {
		if (args->cmd == SCHED_CORE_CMD_EXEC) {
			args->exec_argv_offset = optind;
		} else {
			// -g, -n or -c AND a program to run is provided
			errx(EINVAL, "bad usage, see %s --help",
			     program_invocation_short_name);
		}
	} else if (argc == optind && args->from_pid) {
		// Neither a function (-g, -n, or -c), nor a program to
		// run is given
		args->cmd = SCHED_CORE_CMD_GET;
	}

	verify_arguments(args);
}

int main(int argc, char **argv)
{
	struct args arguments = { 0 };
	arguments.type = PR_SCHED_CORE_SCOPE_THREAD_GROUP;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	parse_arguments(argc, argv, &arguments);

	unsigned long cookie = 0;
	switch (arguments.cmd) {
	case SCHED_CORE_CMD_GET:
		cookie = core_sched_get_cookie(&arguments);
		if (cookie) {
			printf("core scheduling cookie of pid %d is 0x%lx\n",
			       arguments.from_pid, cookie);
		} else {
			printf("pid %d doesn't have a core scheduling cookie\n",
			       arguments.from_pid);
			exit(1);
		}
		break;
	case SCHED_CORE_CMD_CREATE:
		core_sched_create_cookie(&arguments);
		break;
	case SCHED_CORE_CMD_COPY:
		core_sched_copy_cookie(&arguments);
		break;
	case SCHED_CORE_CMD_EXEC:
		core_sched_exec_with_cookie(&arguments, argv);
		break;
	default:
		usage();
		exit(1);
	}
}
