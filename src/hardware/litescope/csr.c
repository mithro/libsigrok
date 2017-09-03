/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Tim 'mithro' Ansell <mithro@mithis.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "csr.h"

#define LOG_PREFIX "litescope/csr"

#define BUF_SIZE (1024-1)

char* csr_entry_str(const struct csr_entry* csr) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(csr);

	switch(csr->type) {
	// Invalid / broken CSR values.
	case CSR_INVALID:
		snprintf(buf, BUF_SIZE, "csr_invalid@%p\n", csr);
		break;
	case CSR_UNKNOWN:
		snprintf(buf, BUF_SIZE, "csr_unknown@%p\n", csr);
		break;
	case CSR_CONSTANT_UNKNOWN:
		snprintf(buf, BUF_SIZE, "csr_constant_unknown@%p\n", csr);
		break;

	// Constants
	case CSR_CONSTANT_NUM:
		snprintf(buf, BUF_SIZE, "csr_constant@%p(%s, %d)", csr, csr->name, csr->constant.value_int);
		break;
	case CSR_CONSTANT_STR:
		snprintf(buf, BUF_SIZE, "csr_constant@%p(%s, %s)", csr, csr->name, csr->constant.value_str);
		break;

	// Actually CSR descriptions
	case CSR_BASE:
		snprintf(buf, BUF_SIZE, "csr_base@%p(%s, %x)", csr, csr->name, csr->location.addr);
		break;

	default: {
		// Type string
		const char* type = NULL;
		switch(csr->type) {
		case CSR_REGISTER:
			type = "csr_reg";
			break;
		case CSR_MEM:
			type = "csr_mem";
			break;

		// Handled by other parts of the switch.
		case CSR_BASE:
		case CSR_UNKNOWN:
		case CSR_CONSTANT_UNKNOWN:
		case CSR_CONSTANT_NUM:
		case CSR_CONSTANT_STR:
		case CSR_INVALID:
			assert(false);
			break;
		}

		// Sanity check the name
		assert(csr->name);
		assert(strlen(csr->name) > 0);

		// Sanity check the address / width
		assert(csr->location.addr != CSR_ERROR);

		// Mode string
		const char* mode = NULL;
		switch(csr->mode) {
		case CSR_RO:
			mode = "ro";
			break;
		case CSR_RW:
			mode = "rw";
			break;
		}
		assert(mode);

		snprintf(
			buf, BUF_SIZE,
			"%s@%p(%s, %x#%d, %s)",
			type, csr,
			csr->name,
			csr->location.addr, csr->location.width,
			mode);
		break;
	}
	}
	return g_strndup(buf, BUF_SIZE);
}

struct csr_entry* _parse_csr_line(char* line) {
	char type[BUF_SIZE] = "\0";
	char name[BUF_SIZE] = "\0";
	char addr[BUF_SIZE] = "\0";
	char width[BUF_SIZE] = "\0";
	char mode[BUF_SIZE] = "\0";

	int matches = sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,]", type, name, addr, width, mode);
	assert(matches >= 3);

	assert(strlen(type) > 0);
	assert(strlen(name) > 0);
	assert(strlen(addr) > 0);

	struct csr_entry* csr = g_malloc0(sizeof(struct csr_entry));

	// Parse the type
	if (strcmp(type, "csr_base") == 0) {
		csr->type = CSR_BASE;
	} else if (strcmp(type, "csr_register") == 0) {
		csr->type = CSR_REGISTER;
	} else if (strcmp(type, "constant") == 0) {
		csr->type = CSR_CONSTANT_UNKNOWN;
	} else if (strcmp(type, "memory_region") == 0) {
		csr->type = CSR_MEM;
	} else {
		sr_err("Invalid value '%s' in column 0 in line %zu.",
			type, (size_t)0);
		return NULL;
	}

	csr->name = g_strdup(name);

	// Parse address/width fields
	csr->location.addr = CSR_ERROR;
	csr->location.width = CSR_ERROR;
	assert(csr->constant.value_int == CSR_ERROR);
	if (strlen(addr) > 0) {
		if (addr[1] == 'x') {
			sscanf(addr, "%x", &(csr->location.addr));
		} else {
			sscanf(addr, "%d", &(csr->location.addr));
		}
	}
	if (strlen(width) > 0) {
		if (width[1] == 'x') {
			sscanf(width, "%x", &(csr->location.width));
		} else {
			sscanf(width, "%d", &(csr->location.width));
		}
	}
	switch(csr->type) {
	case CSR_CONSTANT_UNKNOWN: {
		assert(csr->location.width == CSR_ERROR);
		if (csr->constant.value_int != CSR_ERROR) {
			csr->type = CSR_CONSTANT_NUM;
		} else {
			csr->type = CSR_CONSTANT_STR;
			csr->constant.value_str = g_strdup(addr);
		}
		break;
	}
	case CSR_REGISTER:
	case CSR_MEM:
		assert(csr->location.addr != CSR_ERROR);
		assert(csr->location.width != CSR_ERROR);
		break;
	case CSR_BASE:
		assert(csr->location.addr != CSR_ERROR);
		assert(csr->location.width == CSR_ERROR);
		break;
	default:
		assert(false);
	}

	// Parse the mode
	if (mode != NULL && strcmp(mode, "rw") == 0) {
		csr->mode = CSR_RW;
	} else {
		csr->mode = CSR_RO;
	}

	sr_csr_log(spew, csr);
	return csr;
}

int csr_parse_file(const char* filename, GHashTable** csr_table_ptr) {
	assert(csr_table_ptr != NULL);
	assert(*csr_table_ptr == NULL);

	GHashTable* csr_table = g_hash_table_new(g_str_hash, g_str_equal);

	FILE *stream = g_fopen(filename, "rb");
	if (!stream) {
		sr_err("Failed to open %s: %s", filename, g_strerror(errno));
		goto err;
	}

	// Get filesize
	int64_t filesize = sr_file_get_size(stream);
	if (filesize < 0) {
		sr_err("Failed to get size of %s: %s", filename, g_strerror(errno));
		goto err;
	}

	GString *data = g_string_sized_new(filesize+1);
	data->str[filesize] = '\0';

	size_t count = fread(data->str, 1, data->allocated_len - 1, stream);
	if (count != data->allocated_len - 1 && ferror(stream)) {
		sr_err("Failed to read %s: %s", filename, g_strerror(errno));
	}
	g_string_set_size(data, count);

	char* data_token = data->str;
	char* data_token_saveptr = NULL;
	while(true) {
		char* token = strtok_r(data_token, "\n", &data_token_saveptr);
		data_token = NULL;

		if (token == NULL) {
			break;
		}

		size_t token_len = strlen(token);
		// Deal with Windows line endings..
		if (token[token_len-1] == '\r') {
			token[token_len--] = '\0';
		}

		struct csr_entry* csr = _parse_csr_line(token);
		assert(csr);
		g_hash_table_insert(csr_table, csr->name, csr);
	}

	*csr_table_ptr = csr_table;
	return SR_OK;
err:
	g_hash_table_destroy(csr_table);
	fclose(stream);
	g_string_free(data, TRUE);
	return SR_ERR;
}

int csr_data_width(GHashTable* csr_table) {
	assert(csr_table != NULL);
	// Check the data width, as we only support data_width of 8 at the moment.
	struct csr_entry* csr_data_width = g_hash_table_lookup(csr_table, "csr_data_width");
	assert(csr_data_width);
	int data_width = csr_data_width->constant.value_int;
	assert(data_width == 8);
	return data_width;
}

static int _eb_csr_read(
		struct sr_scpi_dev_inst *conn,
		struct csr_entry* csr, int csr_data_width,
		uint8_t* output_ptr) {
	assert(conn != NULL);
	assert(csr != NULL);
	assert(csr->type == CSR_REGISTER);
	assert(csr_data_width > 0);
	assert(output_ptr != NULL);

	uint32_t csr_data_mask = ~(-1 << csr_data_width);
	assert(csr_data_mask == 0xff);

	struct etherbone_packet* req = etherbone_new(ETHERBONE_READ, csr->location.width);
	//req->record_hdr.base_ret_addr = 0;

	uint32_t addr = csr->location.addr;
	for(unsigned i = 0; i < csr->location.width; i++) {
		sr_spew("Reading address: %x\n", addr);
		req->records[0].values[i].read_addr = addr;
		addr += sizeof(uint32_t);
	}

	// Send the request
	size_t req_size = etherbone_size(req);
	sr_spew("Packet size: %d\n", etherbone_size(req));
	size_t r = sr_scpi_write_data(conn, (char*)etherbone_htobe(req), req_size);
	assert(r == req_size);

	// Read the response
	// - packet header + record[0] header
	struct etherbone_packet* res = etherbone_new(ETHERBONE_WRITE, 0);
	size_t res_hdr_size = etherbone_size(res);
	r = sr_scpi_read_data(conn, (char*)res, res_hdr_size);
	sr_spew("Response size: %d\n", r);
	assert(r == res_hdr_size);

	// - record[0].values
	assert(res->records[0].hdr.wcount == req->records[0].hdr.rcount);
	res = etherbone_grow(res);
	size_t res_full_size = etherbone_size(res);
	r = sr_scpi_read_data(conn, (char*)(&(res->records[0].values[0])), res_full_size-res_hdr_size);

	sr_spew("Response size: %d\n", r);
	assert(r == (res_full_size-res_hdr_size));
	assert(etherbone_check(res));

	// Copy the data out of the response packet
	for(unsigned i = 0; i < csr->location.width; i++) {
#if __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
		size_t dst = csr->location.width-i-1;
		size_t src = i;
#else
		size_t dst = i;
		size_t src = i;
#endif
		assert(dst >= 0);
		assert(src >= 0);
		assert(dst < csr->location.width);
		assert(src < csr->location.width);

		*(output_ptr + dst) = (uint8_t)(res->records[0].values[src].write_value & csr_data_mask);
	}
	return SR_OK;
}

int eb_csr_read_any(
		struct sr_scpi_dev_inst *conn,
		GHashTable* csr_table,
		const char* csr_name,
		uint8_t* output_ptr) {
	assert(conn != NULL);
	assert(csr_table != NULL);
	assert(csr_name != NULL);
	assert(strlen(csr_name) > 0);
	assert(output_ptr != NULL);
	struct csr_entry* csr = g_hash_table_lookup(csr_table, csr_name);
	if (csr == NULL) {
		return SR_ERR;
	}
	return _eb_csr_read(conn, csr, csr_data_width(csr_table), output_ptr);
}

int eb_csr_read_uint32(
		struct sr_scpi_dev_inst *conn,
		GHashTable* csr_table,
		const char* csr_name,
		uint32_t* output_ptr) {
	assert(conn != NULL);
	assert(csr_table != NULL);
	assert(csr_name != NULL);
	assert(strlen(csr_name) > 0);
	assert(output_ptr != NULL);
	struct csr_entry* csr = g_hash_table_lookup(csr_table, csr_name);
	if (csr == NULL) {
		return SR_ERR;
	}

	int data_width = csr_data_width(csr_table);
	assert(csr->location.width == CSR_WIDTH_TYPE(uint32_t, data_width));
	return _eb_csr_read(conn, csr, data_width, (uint8_t*)output_ptr);
}

int eb_csr_read_uint64(
		struct sr_scpi_dev_inst *conn,
		GHashTable* csr_table,
		const char* csr_name,
		uint64_t* output_ptr) {
	assert(conn != NULL);
	assert(csr_table != NULL);
	assert(csr_name != NULL);
	assert(strlen(csr_name) > 0);
	assert(output_ptr != NULL);
	struct csr_entry* csr = g_hash_table_lookup(csr_table, csr_name);
	if (csr == NULL) {
		return SR_ERR;
	}

	int data_width = csr_data_width(csr_table);
	sr_spew("csr width: %d == %d\n", csr->location.width, CSR_WIDTH_TYPE(uint64_t, data_width));
	assert(csr->location.width == CSR_WIDTH_TYPE(uint64_t, data_width));
	return _eb_csr_read(conn, csr, data_width, (uint8_t*)output_ptr);
}
