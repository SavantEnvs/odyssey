/*
 * Server-side SCRAM-SHA-256 (sources/scram.c): what auth.c runs on a
 * client's SASLInitialResponse / SASLResponse payloads, plus the stored
 * verifier parser. Input layout: <client-first> NUL <client-final> NUL
 * <verifier>; missing parts are empty.
 */
#include <odyssey.h>
#include <machinarium/machinarium.h>
#include <machinarium/io.h>
#include <scram.h>

static const char *next_part(const char *p, const char *end, size_t *len)
{
	const char *z = memchr(p, '\0', (size_t)(end - p));
	if (z == NULL) {
		*len = (size_t)(end - p);
		return end;
	}
	*len = (size_t)(z - p);
	return z + 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > (1u << 16))
		return -1;
	const char *p = (const char *)data, *end = p + size;
	size_t l1, l2, l3;
	const char *s1 = p;
	p = next_part(p, end, &l1);
	const char *s2 = p;
	p = next_part(p, end, &l2);
	const char *s3 = p;
	p = next_part(p, end, &l3);

	/* exact-size heap copies (payloads are not NUL-terminated on the wire) */
	char *first = malloc(l1 ? l1 : 1);
	char *final = malloc(l2 ? l2 : 1);
	char *verifier = malloc(l3 + 1);
	if (!first || !final || !verifier)
		goto out;
	memcpy(first, s1, l1);
	memcpy(final, s2, l2);
	memcpy(verifier, s3, l3);
	verifier[l3] = '\0';

	od_scram_state_t state;
	od_scram_state_init(&state);
	if (od_scram_parse_verifier(&state, verifier) != 0) {
		od_scram_state_free(&state);
		od_scram_state_init(&state);
		od_scram_init_from_plain_password(&state, "password");
	}
	if (od_scram_read_client_first_message(&state, first, l1) == 0) {
		/* plain (non-TLS) client connection */
		mm_io_t io;
		memset(&io, 0, sizeof(io));
		char *nonce = NULL;
		size_t nonce_size = 0;
		uint8_t *proof = NULL;
		if (od_scram_read_client_final_message(&io, &state, final, l2,
						       &nonce, &nonce_size,
						       &proof) == 0) {
			/* verify_final_nonce/client_proof need the
			 * server-first message, which needs a machine
			 * (machine_msg); not reachable here */
			od_free(proof);
		}
	}
	od_scram_state_free(&state);
out:
	free(first);
	free(final);
	free(verifier);
	return 0;
}
