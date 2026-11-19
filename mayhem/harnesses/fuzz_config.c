/*
 * Configuration import (sources/cfg/, config.c, rules.c, hba): the path
 * `odyssey --test <conf>` and every config reload take — od_cfg_check()
 * parses the file (cfg scan.l/parse.y), converts the model into
 * od_config/od_rules/od_hba_rules (incl. storage host lists, durations, hba
 * file references) and validates it, without touching running services.
 * The input is written to a scratch file under $TMPDIR, removed afterwards.
 */
#include <odyssey.h>
#include <cfg_import.h>
#include <logger.h>
#include <pid.h>
#include <unistd.h>

static od_pid_t s_pid;
static od_logger_t s_logger;
static int s_init;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > (1u << 20))
		return -1;
	if (!s_init) {
		od_pid_init(&s_pid);
		od_logger_init(&s_logger, &s_pid);
		s_logger.log_stdout = 0; /* keep diagnostics quiet */
		s_init = 1;
	}
	const char *tmp = getenv("TMPDIR");
	char path[4096];
	snprintf(path, sizeof(path), "%s/odyssey-fuzz-XXXXXX.conf",
		 (tmp && *tmp) ? tmp : "/tmp");
	int fd = mkstemps(path, 5);
	if (fd < 0)
		return 0;
	size_t off = 0;
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	close(fd);

	(void)od_cfg_check(&s_logger, path, NULL);

	unlink(path);
	return 0;
}
