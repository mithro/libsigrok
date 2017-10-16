/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Tim 'mithro' Ansell <mithro@mithis.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_LITESCOPE_CSR_H
#define LIBSIGROK_HARDWARE_LITESCOPE_CSR_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "scpi.h"

#include "easy-eb.h"

#define CSR_ERROR (uint32_t)(-1)

enum csr_type {
	CSR_UNKNOWN = 0,
	CSR_BASE = 1,
	CSR_REGISTER,
	CSR_MEM,
	CSR_CONSTANT_UNKNOWN,
	CSR_CONSTANT_NUM,
	CSR_CONSTANT_STR,
	CSR_INVALID = CSR_ERROR,
};

enum csr_mode {
	CSR_RO = 0,
	CSR_RW = 1
};

struct csr_entry {
	enum csr_type type;
	char*         name;
	union {
		struct {
			uint32_t addr;
			uint32_t width;
		} location;
		struct {
			uint32_t value_int;
			char*    value_str;
		 } constant;
	};
	enum csr_mode mode;
};

char* csr_entry_str(const struct csr_entry* csr);

#define sr_csr_log(LEVEL, csr) \
	do { \
		char* msg = csr_entry_str(csr); \
		sr_ ## LEVEL ("%s\n", msg); \
		g_free(msg); \
	} while(false)

bool csr_parse_line(char* line, GHashTable* csr_table);
int csr_parse_file(const char* filename, GHashTable** csr_table_ptr);

int csr_get_constant(const GHashTable* csr_table, const char* name);
int csr_data_width(const GHashTable* csr_table);

/* CSR Reading/writing functions */
enum eb_state {
	EB_STATE_IDLE,
	EB_STATE_SEND_HEAD,
	EB_STATE_SEND_BODY,
	EB_STATE_SEND_HEADnBODY,
	EB_STATE_RECV_HEAD,
	EB_STATE_RECV_BODY,
	EB_STATE_COMPLETE,
};

enum eb_state eb_poll_packet(
	bool expect_response,
	enum eb_state state,
	struct sr_scpi_dev_inst *conn,
	struct etherbone_packet** request,
	struct etherbone_packet** response);

int eb_csr_read_bytes(
	struct sr_scpi_dev_inst *conn,
	const GHashTable* csr_table,
	const char* csr_name,
	uint8_t* output_ptr,
	size_t output_ptr_width);

int eb_csr_write_bytes(
	struct sr_scpi_dev_inst *conn,
	const GHashTable* csr_table,
	const char* csr_name,
	uint8_t* input_ptr,
	size_t input_ptr_width);

#define ROUND_UP(x, y) ((x + y - 1) / y)

#define _EB_CSR_READ_DEF(type) \
	int eb_csr_read_ ## type( \
			struct sr_scpi_dev_inst *conn, \
			const GHashTable* csr_table, \
			const char* csr_name, \
			type* output_ptr)

#define _EB_CSR_WRITE_DEF(type) \
	int eb_csr_write_ ## type( \
			struct sr_scpi_dev_inst *conn, \
			const GHashTable* csr_table, \
			const char* csr_name, \
			type in_value)

#define EB_CSR_FUNCTIONS_DEF(type) \
	_EB_CSR_READ_DEF(type); \
	_EB_CSR_WRITE_DEF(type);

#define EB_CSR_FUNCTIONS(type) \
	_EB_CSR_READ_DEF(type) { \
		return eb_csr_read_bytes( \
			conn, csr_table, csr_name, \
			(uint8_t*)output_ptr, sizeof(type)); \
	} \
	\
	_EB_CSR_WRITE_DEF(type) { \
		return eb_csr_write_bytes( \
			conn, csr_table, csr_name, \
			(uint8_t*)&in_value, sizeof(type)); \
	}

EB_CSR_FUNCTIONS_DEF(uint8_t)
EB_CSR_FUNCTIONS_DEF(uint16_t)
EB_CSR_FUNCTIONS_DEF(uint32_t)
EB_CSR_FUNCTIONS_DEF(uint64_t)

// bool is defined as _Bool
int eb_csr_read_bool(struct sr_scpi_dev_inst *conn, const GHashTable* csr_table, const char* csr_name, bool* output_ptr);
int eb_csr_write_bool(struct sr_scpi_dev_inst *conn, const GHashTable* csr_table, const char* csr_name, bool in_value);

#endif
