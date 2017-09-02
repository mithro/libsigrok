
#include <assert.h>
#include <string.h>
#include <stdlib.h>

//#include <sys/socket.h>

#include "easy-eb.h"

/**
 * Calculate the size (in bytes) of an etherbone packet with the given number
 * of records.
 */
inline size_t _etherbone_size(size_t records) {
	return sizeof(struct etherbone_record_header) + sizeof(struct etherbone_record)*records;
}

/**
 * Calculate the size (in bytes) of an etherbone packet.
 */
size_t etherbone_size(const struct etherbone_packet* packet) {
	return _etherbone_size(packet->record_hdr.rcount + packet->record_hdr.wcount);
}

struct etherbone_packet* etherbone_new(enum etherbone_type type, size_t records) {
	struct etherbone_packet* tx_packet = malloc(_etherbone_size(records));
	tx_packet->magic 	= ETHERBONE_MAGIC;
	tx_packet->version	= ETHERBONE_VERSION;
	tx_packet->no_reads	= 0;
	tx_packet->probe_reply	= 0;
	tx_packet->probe_flag	= 0;
	tx_packet->addr_size	= ETHERBONE_32BITS;
	tx_packet->port_size 	= ETHERBONE_32BITS;

	// Enable reading all 32bits
	tx_packet->record_hdr.bytes_enable = 0xf;

	// rcount / wcount are in bytes
	switch(type) {
	case ETHERBONE_READ:
		tx_packet->record_hdr.rcount = records * 4;
		tx_packet->record_hdr.wcount = 0;
		break;
	case ETHERBONE_WRITE:
		tx_packet->record_hdr.wcount = records * 4;
		tx_packet->record_hdr.rcount = 0;
		break;
	}

	tx_packet->record_hdr.base_ret_addr = 0;
	return tx_packet;
}

struct etherbone_packet* etherbone_grow(struct etherbone_packet* packet, size_t add_records) {
	assert((packet->record_hdr.wcount == 0) || (packet->record_hdr.rcount == 0));
	if (packet->record_hdr.rcount > 0) {
		packet->record_hdr.rcount += add_records;
	}
	if (packet->record_hdr.wcount > 0) {
		packet->record_hdr.wcount += add_records;
	}
	return realloc(packet, etherbone_size(packet));
}





void etherbone_decode(/*struct tcp_socket *s,*/ unsigned char *rxbuf);
void etherbone_decode(/*struct tcp_socket *s,*/ unsigned char *rxbuf)
{
	struct etherbone_packet* rx_packet;
/*	unsigned int i;
	unsigned int addr;
	unsigned int data; */
	unsigned int rcount, wcount;

	assert(rx_packet->magic != ETHERBONE_MAGIC);		/* magic */
	assert(rx_packet->version != ETHERBONE_VERSION);	/* version */
	assert(rx_packet->addr_size != ETHERBONE_32BITS);	/* 32 bits address */
	assert(rx_packet->port_size != ETHERBONE_32BITS);	/* 32 bits data */

	rcount = rx_packet->record_hdr.rcount;
	wcount = rx_packet->record_hdr.wcount;

	assert(rcount == 0);

	// Write from client to us, IE a response to our read request.
	assert(wcount > 0);
	assert(rx_packet->no_reads);

	memcpy(rxbuf, rx_packet->records, wcount*4);

	return;
}


int etherbone_write(uint32_t start_addr, size_t size, uint8_t data[]);
int etherbone_write(uint32_t start_addr, size_t size, uint8_t data[]) {
	/* If start address isn't byte aligned, need to send an initial write
	 * with just the data.
	 */
	assert(start_addr % 4 == 0);

	/* Create the packet */
	struct etherbone_packet* packet = etherbone_init(ETHERBONE_WRITE, size / 4);
	/* Populate the write address, then the data to write */
	packet->record_hdr.base_write_addr = start_addr;
	memcpy((void*)(&(packet->records[0])), data, size);
	/* Send the packet and await the response */
	// FIXME:

	/* If size isn't byte aligned, need to send a final write with just the
	 * remaining data.
	 */
	assert(size % 4 == 0);
}

int etherbone_read(uint32_t start_addr, size_t size, uint8_t data[]);
int etherbone_read(uint32_t start_addr, size_t size, uint8_t data[]) {

	assert(size % 4 == 0);

	struct etherbone_packet* packet = etherbone_init(ETHERBONE_READ, size / 4);
	//pa


}

