/*
 * Admin console command parser (sources/console): od_console_parse() +
 * od_console_node_print(), as console.c runs it on SHOW/KILL/RELOAD/...
 * text sent to the "console" database.
 */
#include <odyssey.h>
#include <alloc/linear.h>
#include <console/ast.h>
#include <console/parser.h>

#define ARENA_SIZE (256 * 1024)
static _Alignas(max_align_t) uint8_t s_arena_buf[ARENA_SIZE];
static od_linear_alloc_t s_arena;
static int s_init;

static void on_error(const char *msg, int position, void *userdata)
{
	(void)msg;
	(void)position;
	(void)userdata;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!s_init) {
		od_linear_alloc_init(&s_arena, s_arena_buf, sizeof(s_arena_buf));
		s_init = 1;
	}
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	od_linear_alloc_reset(&s_arena, 0);
	od_console_node_t *node =
		od_console_parse(buf, size, &s_arena, on_error, NULL);
	if (node != NULL) {
		char out[4096];
		od_console_node_print(node, out, sizeof(out));
	}
	free(buf);
	return 0;
}
