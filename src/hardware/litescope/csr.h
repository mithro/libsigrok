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

#ifndef LIBSIGROK_HARDWARE_LITESCOPE_LITEX_CSR_H
#define LIBSIGROK_HARDWARE_LITESCOPE_LITEX_CSR_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "scpi.h"

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

#define CSR_WIDTH_TYPE(type, width) \
	((uint32_t)(sizeof(type)*8/width))

int csr_parse_file(const char* filename, GHashTable** csr_table_ptr);
bool csr_parse_line(char* line, GHashTable* csr_table);
int csr_data_width(GHashTable* csr_table);

int eb_csr_read_any(
	struct sr_scpi_dev_inst *conn,
	GHashTable* csr_table,
	const char* csr_name,
	uint8_t* output_ptr);
int eb_csr_read_uint32(
	struct sr_scpi_dev_inst *conn,
	GHashTable* csr_table,
	const char* csr_name,
	uint32_t* output_ptr);
int eb_csr_read_uint64(
	struct sr_scpi_dev_inst *conn,
	GHashTable* csr_table,
	const char* csr_name,
	uint64_t* output_ptr);

#endif
