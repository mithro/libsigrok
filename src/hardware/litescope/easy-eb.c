
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

//#include <sys/socket.h>

#include "easy-eb.h"

static size_t _etherbone_record_values(const struct etherbone_packet* pkt) {
	return pkt->records[0].hdr.wcount + pkt->records[0].hdr.rcount;
}

/**
 * Calculate the size (in bytes) of an etherbone packet with the given number
 * of records.
 */
static size_t _etherbone_size(size_t record_values) {
	return ETHERBONE_PACKET_HEADER_LENGTH +
		(ETHERBONE_RECORD_HEADER_LENGTH + ETHERBONE_RECORD_VALUE_LENGTH*record_values);
}

#if __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#include <arpa/inet.h>

static void _etherbone_records_htobe(struct etherbone_packet* pkt) {
	pkt->records[0].hdr.base_raw_addr = htonl(pkt->records[0].hdr.base_raw_addr);
	size_t num_values = _etherbone_record_values(pkt);
	for(size_t i = 0; i < num_values; i++) {
		pkt->records[0].values[i].raw = htonl(pkt->records[0].values[i].raw);
	}
}
struct etherbone_packet* etherbone_htobe(struct etherbone_packet* pkt) {
	// Header
	pkt->hdr.magic = htons(pkt->hdr.magic);
	// records[0]
	_etherbone_records_htobe(pkt);
	return pkt;
}

static void _etherbone_records_betoh(struct etherbone_packet* pkt) {
	pkt->records[0].hdr.base_raw_addr = ntohl(pkt->records[0].hdr.base_raw_addr);
	size_t num_values = _etherbone_record_values(pkt);
	for(size_t i = 0; i < num_values; i++) {
		pkt->records[0].values[i].raw = ntohl(pkt->records[0].values[i].raw);
	}
}
struct etherbone_packet* etherbone_betoh(struct etherbone_packet* pkt) {
	// Header
	pkt->hdr.magic = ntohs(pkt->hdr.magic);
	// records[0]
	_etherbone_records_betoh(pkt);
	return pkt;
}
#else
struct etherbone* etherbone_htobe(struct etherbone* pkt) {}
struct etherbone* etherbone_betoh(struct etherbone* pkt) {}
#endif

/**
 * Calculate the size (in bytes) of an etherbone packet.
 */
size_t etherbone_size(const struct etherbone_packet* pkt) {
	return _etherbone_size(_etherbone_record_values(pkt));
}

struct etherbone_packet* etherbone_new(enum etherbone_type type, size_t record_values) {
	struct etherbone_packet* pkt = malloc(_etherbone_size(record_values));
	pkt->hdr.magic		= ETHERBONE_MAGIC;
	pkt->hdr.version	= ETHERBONE_VERSION;
	pkt->hdr.no_reads	= 0;
	pkt->hdr.probe_reply	= 0;
	pkt->hdr.probe_flag	= 0;
	pkt->hdr.addr_size	= ETHERBONE_32BITS;
	pkt->hdr.port_size 	= ETHERBONE_32BITS;

	// Enable reading all 32bits
	pkt->records[0].hdr.bca = 0;
	pkt->records[0].hdr.rca = 0;
	pkt->records[0].hdr.rff = 0;
	pkt->records[0].hdr.reserved = 0;
	pkt->records[0].hdr.cyc = 0;
	pkt->records[0].hdr.wca = 0;
	pkt->records[0].hdr.wff = 0;
	pkt->records[0].hdr.reserved2 = 0;
	pkt->records[0].hdr.bytes_enable = 0xff;

	pkt->records[0].hdr.base_ret_addr = 0;
	switch(type) {
	case ETHERBONE_READ:
		pkt->records[0].hdr.rcount = record_values;
		pkt->records[0].hdr.wcount = 0;
		break;
	case ETHERBONE_WRITE:
		pkt->records[0].hdr.wcount = record_values;
		pkt->records[0].hdr.rcount = 0;
		break;
	case ETHERBONE_UNKNOWN:
		pkt->records[0].hdr.rcount = 0;
		pkt->records[0].hdr.wcount = 0;
		break;
	}
	return pkt;
}

struct etherbone_packet* etherbone_grow(struct etherbone_packet* pkt) {
	assert((pkt->records[0].hdr.wcount == 0) || (pkt->records[0].hdr.rcount == 0));
	return realloc(pkt, etherbone_size(pkt));
}

struct etherbone_packet* etherbone_add_record_values(struct etherbone_packet* pkt, size_t num_values) {
	if (pkt->records[0].hdr.rcount > 0) {
		pkt->records[0].hdr.rcount += num_values;
	} else if (pkt->records[0].hdr.wcount > 0) {
		pkt->records[0].hdr.wcount += num_values;
	} else {
		assert(false);
	}
	return etherbone_grow(pkt);
}

bool etherbone_check_hostwrite(struct etherbone_packet* pkt) {
	assert(pkt->hdr.magic == ETHERBONE_MAGIC);	/* magic */
	assert(pkt->hdr.version == ETHERBONE_VERSION);	/* version */
	assert(pkt->hdr.addr_size == ETHERBONE_32BITS);	/* 32 bits address */
	assert(pkt->hdr.port_size == ETHERBONE_32BITS);	/* 32 bits data */

	size_t rcount = pkt->records[0].hdr.rcount;
	size_t wcount = pkt->records[0].hdr.wcount;

	assert(rcount == 0);

	// Write from client to us, IE a response to our read request.
	assert(wcount > 0);
	//assert(pkt->hdr.no_reads);

	return true;
}
