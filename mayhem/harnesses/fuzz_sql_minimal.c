/*
 * Minimal SQL parser (sources/sql/minimal), the default routing parser for
 * every client query: od_sql_minimal_parse() + AST print + query-ctx
 * extraction, and od_query_parse_fill_ctx() in MINIMAL mode.
 */
#include <odyssey.h>
#include <alloc/linear.h>
#include <query.h>
#include <client.h>
#include <sql/minimal/ast.h>
#include <sql/minimal/parser.h>

#define ARENA_SIZE (256 * 1024)
static _Alignas(max_align_t) uint8_t s_arena_buf[ARENA_SIZE];
static od_linear_alloc_t s_arena;
static int s_init;

static od_config_query_parsing_t s_minimal = {
	.mode = OD_CONFIG_QUERY_PARSING_MODE_MINIMAL,
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
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	od_linear_alloc_reset(&s_arena, 0);
	od_sql_minimal_node_t *node =
		od_sql_minimal_parse(buf, size, &s_arena, on_error, NULL);
	if (node != NULL) {
		char out[4096];
		od_sql_minimal_node_print(node, out, sizeof(out));
		od_query_ctx_t qc;
		memset(&qc, 0, sizeof(qc));
		od_sql_minimal_extract_query_ctx(node, &qc);
		od_query_ctx_reset(&qc);
	}

	od_query_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	od_linear_alloc_reset(&s_arena, 0);
	od_query_parse_fill_ctx(buf, (uint32_t)size, &s_arena, &ctx,
				&s_minimal);
	od_query_ctx_reset(&ctx);

	free(buf);
	return 0;
}
