// This file is Copyright (c) 2015 Florent Kermarrec <florent@enjoy-digital.fr>
// License: BSD

// See specification at http://www.ohwr.org/attachments/1669/spec.pdf

#ifndef __ETHERBONE_H
#define __ETHERBONE_H

#include <stdbool.h>
#include <stdint.h>

#define scalar_storage_order(x)

#ifdef ETHERBONE_DEBUG
	#include <stdio.h>
	#define print_debug(...) printf(__VA_ARGS__)
#else
	#define print_debug(...) {}
#endif

#include "cassert.h"

#define ETHERBONE_PORT 1234

#define ETHERBONE_MAGIC 	0x4e6f
#define ETHERBONE_VERSION 	1
#define ETHERBONE_8BITS 	1 << 0
#define ETHERBONE_16BITS 	1 << 1
#define ETHERBONE_32BITS 	1 << 2
#define ETHERBONE_64BITS 	1 << 3

enum etherbone_type {
	ETHERBONE_READ = 1,
	ETHERBONE_WRITE = 2,
};

struct etherbone_record_value {
    union {
        uint32_t raw;
        uint32_t write_value;
        uint32_t read_addr;
    };
} __attribute__((packed));

#define ETHERBONE_RECORD_VALUE_LENGTH \
	4
CASSERT(sizeof(struct etherbone_record_value) == ETHERBONE_RECORD_VALUE_LENGTH, easy_eb_h);

// When reading/writing to a FIFO, you don't increase the address after each write.
struct etherbone_record_header {
#if BITS_BIG_ENDIAN != 1
    uint8_t reserved2	: 1;
    uint8_t wff		: 1;  // WriteFIFO        - (W)rite (F)I(F)O
    uint8_t wca		: 1;  // WriteToCfgSpace  - (W)rite to (C)onfig (A)dress
    uint8_t cyc		: 1;  // DropCycle        - Drop(Cyc)le
    uint8_t reserved	: 1;
    uint8_t rff		: 1;  // ReadFIFO         - (R)ead (F)I(F)O
    uint8_t rca		: 1;  // ReadFromCfgSpace - (R)ead from (C)onfig (A)dress
    uint8_t bca		: 1;  // ReplyToCfgSpace  - ??? (C)onfig (A)dress
#else
    uint8_t bca		: 1;  // ReplyToCfgSpace  - ??? (C)onfig (A)dress
    uint8_t rca		: 1;  // ReadFromCfgSpace - (R)ead from (C)onfig (A)dress
    uint8_t rff		: 1;  // ReadFIFO         - (R)ead (F)I(F)O
    uint8_t reserved	: 1;
    uint8_t cyc		: 1;  // DropCycle        - Drop(Cyc)le
    uint8_t wca		: 1;  // WriteToCfgSpace  - (W)rite to (C)onfig (A)dress
    uint8_t wff		: 1;  // WriteFIFO        - (W)rite (F)I(F)O
    uint8_t reserved2	: 1;
#endif
    uint8_t bytes_enable;     // Select
    uint8_t wcount;           // Writes
    uint8_t rcount;           // Reads
    union {
	uint32_t base_raw_addr;
        uint32_t base_write_addr;
        uint32_t base_ret_addr;
    };
} __attribute__((packed));

#define ETHERBONE_RECORD_HEADER_LENGTH \
	(4+sizeof(uint32_t))
CASSERT(sizeof(struct etherbone_record_header) == ETHERBONE_RECORD_HEADER_LENGTH, easy_eb_h);

struct etherbone_record {
	struct etherbone_record_header hdr;
	struct etherbone_record_value values[];
} __attribute__((packed, scalar_storage_order("big-endian")));

struct etherbone_packet_header {
	uint16_t magic;
#if BITS_BIG_ENDIAN != 1
	uint8_t probe_flag	: 1;
	uint8_t probe_reply 	: 1;
	uint8_t no_reads	: 1;
	uint8_t reserved	: 1;
	uint8_t version		: 4;

	uint8_t port_size	: 4;
	uint8_t addr_size	: 4;
#else
	uint8_t version		: 4;
	uint8_t reserved	: 1;
	uint8_t no_reads	: 1;
	uint8_t probe_reply 	: 1;
	uint8_t probe_flag	: 1;

	uint8_t addr_size	: 4;
	uint8_t port_size	: 4;
#endif
	uint32_t padding;
} __attribute__((packed, aligned(8)));

#define ETHERBONE_PACKET_HEADER_LENGTH \
	8
CASSERT(sizeof(struct etherbone_packet_header) == ETHERBONE_PACKET_HEADER_LENGTH, easy_eb_h);

struct etherbone_packet {
	struct etherbone_packet_header hdr;
	struct etherbone_record records[1];
} __attribute__((packed, scalar_storage_order("big-endian"), aligned(8)));

#define ETHERBONE_PACKET_MIN \
	ETHERBONE_PACKET_HEADER_LENGTH + ETHERBONE_RECORD_HEADER_LENGTH;

struct etherbone_packet* etherbone_htobe(struct etherbone_packet* pkt);
struct etherbone_packet* etherbone_betoh(struct etherbone_packet* pkt);

/**
 * Calculate the size (in bytes) of an etherbone packet.
 */
size_t etherbone_size(const struct etherbone_packet* pkt);

/**
 * Create a new etherbone packet of the type with the records.
 */
struct etherbone_packet* etherbone_new(enum etherbone_type type, size_t record_values);

/**
 * Extend an etherbone packet to now contain more records.
 */
struct etherbone_packet* etherbone_grow(struct etherbone_packet* pkt);

struct etherbone_packet* etherbone_add_record_values(struct etherbone_packet* pkt, size_t num_records);

bool etherbone_check(struct etherbone_packet* pkt);

#endif
