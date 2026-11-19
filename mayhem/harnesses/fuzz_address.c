/*
 * Address parsers (sources/address.c): the storage "host" list parser
 * od_parse_addresses() (host[:port][(zone)], unix sockets, comma lists)
 * and the hba CIDR prefix parser od_address_range_read_prefix() for
 * IPv4 and IPv6 rules. Both take operator config text.
 */
#include <odyssey.h>
#include <sys/socket.h>
#include <address.h>
#include <od_memory.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > (1u << 16))
		return -1;
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	od_address_t *addrs = NULL;
	size_t count = 0;
	if (od_parse_addresses(buf, &addrs, &count) == 0 && addrs != NULL) {
		for (size_t i = 0; i < count; ++i) {
			char out[512];
			od_address_to_str(&addrs[i], out, sizeof(out));
			od_address_destroy(&addrs[i]);
		}
	}
	od_free(addrs);

	od_address_range_t r4, r6;
	memset(&r4, 0, sizeof(r4));
	memset(&r6, 0, sizeof(r6));
	r4.addr.ss_family = AF_INET;
	r6.addr.ss_family = AF_INET6;
	(void)od_address_range_read_prefix(&r4, buf);
	(void)od_address_range_read_prefix(&r6, buf);

	free(buf);
	return 0;
}
