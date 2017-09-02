
#include <assert.h>

#include "easy-eb.h"



void etherbone_decode(struct tcp_socket *s, unsigned char *rxbuf)
{
	unsigned int i;
	unsigned int addr;
	unsigned int data;
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
	assert(rx_packet->record_hdr->no_reads);

	return;
}

struct etherbone_packet* etherbone_init(enum etherbone_type type, size_t records) {
	struct etherbone_packet* packet = malloc(ETHERBONE_HEADER_LENGTH + sizeof(etherbone_record)*records);
	tx_packet->magic 	= ETHERBONE_MAGIC;
	tx_packet->version	= ETHERBONE_VERSION;
	tx_packet->no_reads	= 0;
	tx_packet->probe_reply	= 0;
	tx_packet->probe_flag	= 0;
	tx_packet->addr_size	= ETHERBONE_32BITS;
	tx_packet->port_size 	= ETHERBONE_32BITS;

	// Enable reading all 32bits
	tx_packet->bytes_enable = 0xf;

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

	tx_packet->base_ret_addr = 0;
	return packet;
}

int etherbone_write(uint32_t start_addr, size_t size, byte[] data) {
	/* If start address isn't byte aligned, need to send an initial write
	 * with just the data.
	 */
	assert(start_addr % 4 == 0);

	/* Create the packet */
	struct etherbone_packet* packet = etherbone_init(ETHERBONE_WRITE, size / 4);
	/* Populate the write address, then the data to write */
	tx_packet->record_hdr.base_write_addr = start_addr;
	memcpy((void*)(&(eb_packet.records[0])), byte, size);
	/* Send the packet and await the response */
	

	/* If size isn't byte aligned, need to send a final write with just the
	 * remaining data.
	 */
	assert(size % 4 == 0);
}

int etherbone_read(uint32_t start_addr, size_t size, byte[] data) {

	assert(size % 4 == 0);

	struct etherbone_packet* packet = etherbone_init(ETHERBONE_READ, size / 4);
	pa


}

