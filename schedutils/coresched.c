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

typedef enum {
	SCHED_CORE_SCOPE_PID = PR_SCHED_CORE_SCOPE_THREAD,
	SCHED_CORE_SCOPE_TGID = PR_SCHED_CORE_SCOPE_THREAD_GROUP,
	SCHED_CORE_SCOPE_PGID = PR_SCHED_CORE_SCOPE_PROCESS_GROUP,
} core_sched_type_t;

typedef enum {
	SCHED_CORE_CMD_NONE = 0,
	SCHED_CORE_CMD_GET = 1,
	SCHED_CORE_CMD_CREATE = 2,
	SCHED_CORE_CMD_COPY = 4,
	SCHED_CORE_CMD_EXEC = 8,
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

unsigned long core_sched_get_cookie(struct args *args)
{
	unsigned long cookie = 0;
	int prctl_errno = prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET,
				args->from_pid, SCHED_CORE_SCOPE_PID, &cookie);
	if (prctl_errno) {
		errx(-prctl_errno, "Failed to get cookie from PID %d",
		     args->from_pid);
	}
	return cookie;
}

void core_sched_create_cookie(struct args *args)
{
	int prctl_errno = prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE,
				args->from_pid, args->type, 0);
	if (prctl_errno) {
		errx(-prctl_errno, "Failed to create cookie for PID %d",
		     args->from_pid);
	}
}

void core_sched_pull_cookie(pid_t from)
{
	int prctl_errno = prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM, from,
				SCHED_CORE_SCOPE_PID, 0);
	if (prctl_errno) {
		errx(-prctl_errno, "Failed to pull cookie from PID %d", from);
	}
}

void core_sched_push_cookie(pid_t to, core_sched_type_t type)
{
	int prctl_errno =
		prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_TO, to, type, 0);
	if (prctl_errno) {
		errx(-prctl_errno, "Failed to push cookie to PID %d", to);
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
		errx(EINVAL, "when --exec is provided, a program name "
			     "has to be given.");
	}

	// Move the argument list to the first argument of the program
	argv = &argv[args->exec_argv_offset];

	pid_t pid = fork();
	if (pid == -1) {
		errx(errno, "Failed to spawn new process");
	}

	if (!pid) {
		// If a source PID is provided, try to copy the cookie from
		// that PID. Otherwise, create a brand new cookie with the
		// provided type.
		if (args->from_pid) {
			core_sched_pull_cookie(args->from_pid);
		} else {
			args->from_pid = getpid();
			core_sched_create_cookie(args);
		}
		if (execvp(argv[0], argv)) {
			errexec(argv[0]);
		}
	} else {
		int status = 0;
		waitpid(pid, &status, 0);
		exit(status);
	}
}

core_sched_type_t parse_core_sched_type(char *str)
{
	if (!strncmp(str, "pid\0", 4)) {
		return SCHED_CORE_SCOPE_PID;
	} else if (!strncmp(str, "tgid\0", 5)) {
		return SCHED_CORE_SCOPE_TGID;
	} else if (!strncmp(str, "pgid\0", 5)) {
		return SCHED_CORE_SCOPE_PGID;
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
	fprintf(stdout, _(" %s --exec [-s <PID>] -- PROGRAM ARGS... \n"),
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
	fputsln(_(" -e, --exec              execute a program with a new core scheduling\n"
		  "                           cookie."),
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
	if (args->cmd == SCHED_CORE_CMD_NONE) {
		usage();
	}

	// Check if the value of args->cmd is a power of 2
	// In that case, only a single function option was set.
	if (!(args->cmd && !(args->cmd & (args->cmd - 1)))) {
		errx(EINVAL, "Cannot do more than one function at a time.");
	}

	if (args->from_pid < 0) {
		errx(EINVAL, "source PID cannot be negative");
	}

	if (args->to_pid < 0) {
		errx(EINVAL, "destination PID cannot be negative");
	}

	if (args->from_pid == 0 && args->cmd == SCHED_CORE_CMD_COPY) {
		errx(EINVAL, "valid argument to --source is required");
	}

	if (args->to_pid == 0 && args->cmd == SCHED_CORE_CMD_COPY) {
		errx(EINVAL, "valid argument to --dest is required");
	}

	if (args->from_pid == 0 && args->cmd != SCHED_CORE_CMD_EXEC) {
		errx(EINVAL, "PID cannot be zero");
	}

	return true;
}

void parse_arguments(int argc, char **argv, struct args *args)
{
	int c;

	enum {
		OPT_GET = 'g',
		OPT_NEW = 'n',
		OPT_COPY = 'c',
		OPT_EXEC = 'e',
		OPT_SRC = 's',
		OPT_DEST = 'd',
		OPT_TYPE = 't',
		OPT_VERSION = 'V',
		OPT_HELP = 'h'
	};

	static const struct option longopts[] = {
		{ "get", required_argument, NULL, OPT_GET },
		{ "new", required_argument, NULL, OPT_NEW },
		{ "copy", no_argument, NULL, OPT_COPY },
		{ "exec", no_argument, NULL, OPT_EXEC },
		{ "source", required_argument, NULL, OPT_SRC },
		{ "destination", required_argument, NULL, OPT_DEST },
		{ "type", required_argument, NULL, OPT_TYPE },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "g:n:ces:d:t:Vh", longopts,
				NULL)) != -1)
		switch (c) {
		case OPT_GET:
			args->cmd |= SCHED_CORE_CMD_GET;
			args->from_pid = strtos32_or_err(
				optarg, "Failed to parse PID for --get");
			break;
		case OPT_NEW:
			args->cmd |= SCHED_CORE_CMD_CREATE;
			args->from_pid = strtos32_or_err(
				optarg, "Failed to parse PID for --new");
			break;
		case OPT_COPY:
			args->cmd |= SCHED_CORE_CMD_COPY;
			break;
		case OPT_EXEC:
			args->cmd |= SCHED_CORE_CMD_EXEC;
			break;
		case OPT_SRC:
			args->from_pid = strtos32_or_err(
				optarg, "Failed to parse PID for --source");
			break;
		case OPT_DEST:
			args->to_pid = strtos32_or_err(
				optarg, "Failed to parse PID for --dest");
			break;
		case OPT_TYPE:
			args->type = parse_core_sched_type(optarg);
			break;
		case OPT_VERSION:
			print_version(EXIT_SUCCESS);
		case OPT_HELP:
			usage();
		default:
			errtryhelp(EXIT_FAILURE);
		}

	if (argc > optind) {
		args->exec_argv_offset = optind;
	}
	verify_arguments(args);
}

int main(int argc, char **argv)
{
	struct args arguments = { 0 };
	arguments.type = SCHED_CORE_SCOPE_TGID;

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
