// This file is Copyright (c) 2015 Florent Kermarrec <florent@enjoy-digital.fr>
// License: BSD

// See specification at http://www.ohwr.org/attachments/1669/spec.pdf

#ifndef __ETHERBONE_H
#define __ETHERBONE_H

#ifdef ETHERBONE_DEBUG
	#include <stdio.h>
	#define print_debug(...) printf(__VA_ARGS__)
#else
	#define print_debug(...) {}
#endif

#define ETHERBONE_PORT 1234

#define ETHERBONE_MAGIC 	0x4e6f
#define ETHERBONE_VERSION 	1
#define ETHERBONE_8BITS 	0x1
#define ETHERBONE_16BITS 	0x2
#define ETHERBONE_32BITS 	0x4
#define ETHERBONE_64BITS 	0x8

enum etherbone_type {
	ETHERBONE_READ = 1;
	ETHERBONE_WRITE = 2;
};

#define ETHERBONE_HEADER_LENGTH 12

struct etherbone_record {
    union {
        uint32_t write_value;
        uint32_t read_addr;
    };
} __attribute__((packed));

// When reading/writing to a FIFO, you don't increase the address after each write.
struct etherbone_record_header {
    unsigned int bca:		1;  // ReplyToCfgSpace  - ??? (C)onfig (A)dress
    unsigned int rca:		1;  // ReadFromCfgSpace - (R)ead from (C)onfig (A)dress
    unsigned int rff: 		1;  // ReadFIFO         - (R)ead (F)I(F)O
    unsigned int reserved: 	1;
    unsigned int cyc: 		1;  // DropCycle        - Drop(Cyc)le
    unsigned int wca: 		1;  // WriteToCfgSpace  - (W)rite to (C)onfig (A)dress
    unsigned int wff: 		1;  // WriteFIFO        - (W)rite (F)I(F)O
    unsigned int reserved2:	1;
    unsigned char byte_enable;      // Select
    unsigned char wcount;           // Writes
    unsigned char rcount;           // Reads
    union {
        uint32_t base_write_addr;
        uint32_t base_ret_addr;
    };
} __attribute__((packed));

struct etherbone_packet {
    uint16_t magic;
    unsigned int version: 	4;
    unsigned int reserved: 	1;
    unsigned int no_reads: 	1;
    unsigned int probe_reply: 	1;
    unsigned int probe_flag: 	1;
    unsigned int addr_size: 	4;
    unsigned int port_size: 	4;
    uint32_t padding;

    struct etherbone_record_header record_hdr;
    struct etherbone_record record[];
} __attribute__((packed, aligned(8)));

#endif
