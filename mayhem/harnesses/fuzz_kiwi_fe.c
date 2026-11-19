/*
 * PostgreSQL server -> Odyssey message readers (kiwi/fe_read.h): what
 * backend.c / auth.c parse from a backend during connect and auth —
 * Authentication* (SASL mechanism list, MD5 salt), ErrorResponse fields,
 * ParameterStatus, BackendKeyData, ReadyForQuery, NegotiateProtocolVersion.
 */
#include <odyssey.h>
#include <kiwi/kiwi.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* machinarium delivers whole messages, header included
	 * (kiwi_read_size() asserts >= 5 bytes) */
	if (size < sizeof(kiwi_header_t) || size > (1u << 24))
		return -1;
	char *msg = malloc(size);
	if (msg == NULL)
		return 0;
	memcpy(msg, data, size);
	uint32_t sz = (uint32_t)size;
	volatile size_t sink = 0;

	switch ((unsigned char)msg[0]) {
	case KIWI_BE_AUTHENTICATION: {
		uint32_t type;
		char salt[4];
		char *ad = NULL;
		size_t adsz = 0;
		if (kiwi_fe_read_auth(msg, sz, &type, salt, &ad, &adsz) == 0)
			sink += type + adsz;
		break;
	}
	case KIWI_BE_ERROR_RESPONSE:
	case KIWI_BE_NOTICE_RESPONSE: {
		kiwi_fe_error_t err;
		memset(&err, 0, sizeof(err));
		if (kiwi_fe_read_error(msg, sz, &err) == 0) {
			if (err.message)
				sink += strlen(err.message);
			if (err.code)
				sink += strlen(err.code);
		}
		break;
	}
	case KIWI_BE_PARAMETER_STATUS: {
		char *n, *v;
		uint32_t nl, vl;
		if (kiwi_fe_read_parameter(msg, sz, &n, &nl, &v, &vl) == 0)
			sink += nl + vl;
		break;
	}
	case KIWI_BE_BACKEND_KEY_DATA: {
		kiwi_key_t key;
		memset(&key, 0, sizeof(key));
		/* both protocol 3.0 and 3.2 (variable-length keys) */
		(void)kiwi_fe_read_key(msg, sz, &key, PG_PROTOCOL(3, 0));
		memset(&key, 0, sizeof(key));
		(void)kiwi_fe_read_key(msg, sz, &key, PG_PROTOCOL(3, 2));
		break;
	}
	case KIWI_BE_READY_FOR_QUERY: {
		int status;
		if (kiwi_fe_read_ready(msg, sz, &status) == 0)
			sink += status;
		break;
	}
	case KIWI_BE_NEGOTIATE_PROTOCOL_VERSION: {
		uint32_t v;
		if (kiwi_fe_read_protocol_negotiation(msg, sz, &v) == 0)
			sink += v;
		break;
	}
	default:
		break;
	}
	(void)sink;
	free(msg);
	return 0;
}
