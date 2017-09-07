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

#include <assert.h>
#include <string.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#include "scpi.h"
#include "simple-csv.h"

#include "analyzer.h"

#define LOG_PREFIX "litescope/analyzer"

#define BUF_SIZE (1024-1)

char* analyzer_signal_str(const struct analyzer_signal* signal) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(signal);

	snprintf(buf, BUF_SIZE, "signal@%p(%s@%d, %d)\n",
		 signal, signal->name, signal->group, signal->bits);
	return g_strndup(buf, BUF_SIZE);
}

char* analyzer_config_str(const struct analyzer_config* config) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(config);

	snprintf(buf, BUF_SIZE, "config@%p(width:%d, depth:%d, cd:%d, groups:%d)\n",
		 config,
		 config->data_width, config->data_depth,
		 config->cd_ratio, config->num_groups);
	return g_strndup(buf, BUF_SIZE);
}

bool analyzer_parse_line(char* line, struct analyzer* an) {
	assert(an != NULL);
	assert(an->signals != NULL);

	char type[BUF_SIZE] = "\0";
	char group[BUF_SIZE] = "\0";
	char name[BUF_SIZE] = "\0";
	char value[BUF_SIZE] = "\0";

	int matches = sscanf(line, "%[^,],%[^,],%[^,],%[^,]", type, group, name, value);
	assert(matches >= 4);

	assert(strlen(type) > 0);
	assert(strlen(group) > 0);
	assert(strlen(name) > 0);
	assert(strlen(value) > 0);

	if (strcmp(type, "config") == 0) {
		if (strcmp(name, "dw") == 0) {
			sscanf(value, "%d", &(an->config.data_width));
		} else if (strcmp(name, "depth") == 0) {
			sscanf(value, "%d", &(an->config.data_depth));
		} else if (strcmp(name, "cd_ratio") == 0) {
			sscanf(value, "%d", &(an->config.cd_ratio));
		} else {
			sr_err("Invalid config value '%s' in column 0 in line %zu.",
				name, (size_t)0);
			return false;
		}
	} else if (strcmp(type, "signal") == 0) {
		struct analyzer_signal* signal = g_malloc0(sizeof(struct analyzer_signal));

		sscanf(group, "%d", &(signal->group));
		if (signal->group+1 > an->config.num_groups) {
			an->config.num_groups = signal->group+1;
		}

		signal->name = g_strdup(name);
		sscanf(value, "%d", &(signal->bits));

		sr_analyzer_log(spew, analyzer_signal_str, signal);
		g_hash_table_insert(an->signals, signal->name, signal);
	} else {
		sr_err("Invalid config value '%s' in column 0 in line %zu.",
			type, (size_t)0);
		return false;
	}
	return true;

}

int analyzer_parse_file(const char* filename, struct analyzer** an_ptr) {
	assert(an_ptr != NULL);
	assert(*an_ptr == NULL);

	struct analyzer* an = g_malloc0(sizeof(struct analyzer));
	an->signals = g_hash_table_new(g_str_hash, g_str_equal);

	if (csv_parse_file(filename, (csv_parse_line_t)(&analyzer_parse_line), (void*)an) != SR_OK) {
		g_hash_table_destroy(an->signals);
		g_free(an);
		return SR_ERR;
	} else {
		sr_analyzer_log(spew, analyzer_config_str, &(an->config));
		*an_ptr = an;
		return SR_OK;
	}
}

int analyzer_run(struct sr_scpi_dev_inst *conn, const struct analyzer* an) {
	// Drain the storage_mem_data fifo

	//eb_csr_write_uint16(conn, "analyzer_storage_offset", x);
	//eb_csr_write_uint16(conn, "analyzer_storage_length", x);
	//eb_csr_write_bool(conn, "analyzer_storage_run", true);

}

bool analyzer_check(struct sr_scpi_dev_inst *conn, const struct analyzer* an) {
	bool r;
	assert(eb_csr_read_bool(conn, "analyzer_storage_idle", &r) == SR_OK);
	return r;
}


int analyzer_download(struct sr_scpi_dev_inst *conn, const struct analyzer* an) {
	if (!analyzer_check(conn, an)) {
		return SR_ERR;
	}

	// Work out the amount of data in storage_mem_data fifo
	uint16_t storage_length;
	eb_csr_read_int16_t(conn, an->csrs, "analyzer_storage_length", &storage_length);
	int length = storage_length / an->config.cd_ratio;

	// Read the data out of the storage_mem_data fifo
	for(int i = 1; i < length+1; i++ ) {
//		eb_csr_read_any(conn, an->csrs, "analyzer_storage_mem_data", data[i]);
		eb_csr_write_bool(conn, an->csrs, "analyzer_storage_mem_ready", true);
	}

}
