/*
 * Startup packet parsing (kiwi_be_read_startup in be_read.h, options.c,
 * var.c): the first bytes any client sends — length, protocol version /
 * SSL / GSS / CancelRequest codes, key=value parameters, the PGOPTIONS
 * "options" tokenizer and the kiwi_vars update.
 */
#include <odyssey.h>
#include <kiwi/kiwi.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > (1u << 20))
		return -1;
	char *buf = malloc(size ? size : 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);

	kiwi_be_startup_t su;
	kiwi_vars_t vars;
	kiwi_be_startup_init(&su);
	kiwi_vars_init(&vars);
	(void)kiwi_be_read_startup(buf, (uint32_t)size, &su, &vars);
	kiwi_be_startup_free(&su);
	kiwi_vars_free(&vars);

	free(buf);
	return 0;
}
