/*
 * Full PostgreSQL-grammar SQL parser (sources/sql/full), reached the way the
 * router does it: od_query_parse_fill_ctx() with query_parsing mode FULL,
 * which calls od_sql_full_parse() and walks the AST. Client SQL text is
 * untrusted (Query / Parse messages).
 */
#include <odyssey.h>
#include <alloc/linear.h>
#include <query.h>
#include <client.h>
#include <sql/full/parser.h>

#define ARENA_SIZE (5 * 1024 * 1024)
static _Alignas(max_align_t) uint8_t s_arena_buf[ARENA_SIZE];
static od_linear_alloc_t s_arena;
static int s_init;

static od_config_query_parsing_t s_full = {
	.mode = OD_CONFIG_QUERY_PARSING_MODE_FULL,
	.max_query_len = 1 << 20,
};

static void on_error(const char *msg, void *userdata)
{
	(void)msg;
	(void)userdata;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!s_init) {
		od_linear_alloc_init(&s_arena, s_arena_buf, sizeof(s_arena_buf));
		s_init = 1;
	}
	/* frontend.c hands the parser a NUL-terminated query (kiwi readers
	 * require the trailing NUL since 7b23def2); keep that contract */
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	od_linear_alloc_reset(&s_arena, 0);
	(void)od_sql_full_parse(&s_arena, buf, size, on_error, NULL);

	od_query_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	od_linear_alloc_reset(&s_arena, 0);
	od_query_parse_fill_ctx(buf, (uint32_t)size, &s_arena, &ctx, &s_full);
	od_query_ctx_reset(&ctx);

	free(buf);
	return 0;
}
