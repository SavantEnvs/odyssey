/*
 * Client -> Odyssey wire message readers (sources/include/kiwi/be_read.h),
 * the code frontend.c / auth.c / relay paths run on every message a client
 * sends. The message is the whole input (type byte + int32 length + body);
 * its type byte selects the reader the way the frontend dispatches on it.
 */
#include <odyssey.h>
#include <kiwi/kiwi.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Machinarium only hands kiwi a message after reading its full
	 * 5-byte header (kiwi_read_size() asserts it), so shorter inputs
	 * cannot reach these readers. */
	if (size < sizeof(kiwi_header_t) || size > (1u << 24))
		return -1;

	/* exact-size heap copy so ASan sees overreads */
	char *msg = malloc(size);
	if (msg == NULL)
		return 0;
	memcpy(msg, data, size);
	uint32_t sz = (uint32_t)size;
	volatile size_t sink = 0;

	char *a, *b;
	uint32_t alen, blen;
	switch ((unsigned char)msg[0]) {
	case KIWI_FE_QUERY:
		if (kiwi_be_read_query(msg, sz, &a, &alen) == 0)
			sink += strlen(a);
		break;
	case KIWI_FE_PARSE: {
		if (kiwi_be_read_parse(msg, sz, &a, &alen, &b, &blen) == 0)
			sink += alen + blen + strlen(b);
		kiwi_prepared_statement_t dest;
		memset(&dest, 0, sizeof(dest));
		if (kiwi_be_read_parse_dest(msg, sz, &dest) == 0)
			sink += dest.operator_name_len + dest.description_len;
		sink += kiwi_be_parse_opname_offset(msg, sz);
		break;
	}
	case KIWI_FE_BIND:
		sink += kiwi_be_bind_opname_offset(msg, sz);
		if (kiwi_be_read_bind_names(msg, sz, &a, &alen, &b, &blen) == 0)
			sink += alen + blen;
		break;
	case KIWI_FE_DESCRIBE: {
		kiwi_fe_describe_type_t t;
		sink += kiwi_be_describe_opname_offset(msg, sz);
		if (kiwi_be_read_describe(msg, sz, &a, &alen, &t) == 0)
			sink += alen;
		break;
	}
	case KIWI_FE_EXECUTE:
		if (kiwi_be_read_execute(msg, sz, &a, &alen) == 0)
			sink += alen;
		break;
	case KIWI_FE_CLOSE: {
		kiwi_fe_close_type_t t;
		if (kiwi_be_read_close(msg, sz, &a, &alen, &t) == 0)
			sink += alen;
		break;
	}
	case KIWI_FE_PASSWORD_MESSAGE: {
		/* 'p' carries PasswordMessage, SASLInitialResponse and
		 * SASLResponse; auth.c picks the reader by auth state */
		kiwi_password_t pw;
		memset(&pw, 0, sizeof(pw));
		if (kiwi_be_read_password(msg, sz, &pw) == 0)
			free(pw.password);
		char *mech, *ad;
		size_t adsz;
		if (kiwi_be_read_authentication_sasl_initial(msg, sz, &mech,
							     &ad, &adsz) == 0)
			sink += strlen(mech) + adsz;
		if (kiwi_be_read_authentication_sasl(msg, sz, &ad, &adsz) == 0)
			sink += adsz;
		break;
	}
	default:
		break;
	}
	(void)sink;
	free(msg);
	return 0;
}
