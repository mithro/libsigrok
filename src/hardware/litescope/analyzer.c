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

#include "csr.h"
#include "simple-csv.h"

#include "analyzer.h"

#define LOG_PREFIX "litescope/analyzer"

#define BUF_SIZE (1024-1)

struct analyzer* analyzer_append_signals(struct analyzer* an) {
	assert(an != NULL);
	an->signal_groups++;
	struct analyzer *new_an = g_realloc(
		an, sizeof(struct analyzer) + sizeof(GHashTable*) * an->signal_groups);
	assert(new_an != NULL);
	GHashTable** ht = &(new_an->signals[new_an->signal_groups-1]);
	*ht = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(*ht, "_shift", g_malloc0(sizeof(size_t)));
	return new_an;
}

GHashTable* analyzer_signals(struct analyzer* an, size_t group_num) {
	assert(an != NULL);
	assert(group_num < an->signal_groups);
	GHashTable* ht = an->signals[group_num];
	assert(ht != NULL);
	return ht;
}

size_t* _analyzer_signals_shift(struct analyzer* an, size_t group_num) {
	GHashTable* ht = analyzer_signals(an, group_num);
	size_t* shift = g_hash_table_lookup(ht, "_shift");
	assert(shift != NULL);
	return shift;
}

void analyzer_free(struct analyzer** an_ptr) {
	assert(an_ptr != NULL);
	assert(*an_ptr != NULL);
	for(size_t i = 0; i < (*an_ptr)->signal_groups; i++) {
		g_hash_table_destroy((*an_ptr)->signals[i]);
		(*an_ptr)->signals[i] = NULL;
	}
	if ((*an_ptr)->csrs != NULL) {
		g_hash_table_destroy((*an_ptr)->csrs);
		(*an_ptr)->csrs = NULL;
	}
	g_free(*an_ptr);
	*an_ptr = NULL;
}

char* analyzer_signal_str(const struct analyzer_signal* signal, size_t group) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(signal);

	snprintf(buf, BUF_SIZE, "signal%zd@%p(%s, %d bits (x >> %d & 0x%x))\n",
		 group, signal, signal->name, signal->bits, signal->shift, signal->mask);
	return g_strndup(buf, BUF_SIZE);
}

char* analyzer_config_str(const struct analyzer_config* config, size_t signal_groups) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(config);

	snprintf(buf, BUF_SIZE, "config@%p(width:%d, depth:%d, cd_ratio:%d, groups:%zd)\n",
		 config,
		 config->data_width, config->data_depth,
		 config->cd_ratio,
		 signal_groups);
	return g_strndup(buf, BUF_SIZE);
}

bool analyzer_parse_line(char* line, struct analyzer** an_ptr) {
	assert(an_ptr != NULL);
	assert(*an_ptr != NULL);

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
			sscanf(value, "%d", &((*an_ptr)->config.data_width));
		} else if (strcmp(name, "depth") == 0) {
			sscanf(value, "%d", &((*an_ptr)->config.data_depth));
		} else if (strcmp(name, "cd_ratio") == 0) {
			sscanf(value, "%d", &((*an_ptr)->config.cd_ratio));
		} else {
			sr_err("Invalid config value '%s' in column 0 in line %zu.",
				name, (size_t)0);
			return false;
		}
	} else if (strcmp(type, "signal") == 0) {
		struct analyzer_signal* signal = g_malloc0(sizeof(struct analyzer_signal));

		size_t group_num = 0;
		sscanf(group, "%zd", &group_num);
		while (group_num >= (*an_ptr)->signal_groups) {
			*an_ptr = analyzer_append_signals(*an_ptr);
		}
		size_t *shift = _analyzer_signals_shift(*an_ptr, group_num);
		assert(shift != NULL);

		signal->name = g_strdup(name);
		sscanf(value, "%d", &(signal->bits));

		signal->mask = ~(-1 << signal->bits);
		signal->shift = *shift;
		*shift += signal->bits;

		sr_analyzer_log(spew, analyzer_signal_str, signal, group_num);
		GHashTable *ht = analyzer_signals(*an_ptr, group_num);
		assert(ht != NULL);
		g_hash_table_insert(ht, signal->name, signal);
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
	if (csv_parse_file(filename, (csv_parse_line_t)(&analyzer_parse_line), (void*)&an) != SR_OK) {
		analyzer_free(&an);
		return SR_ERR;
	} else {
		sr_analyzer_log(spew, analyzer_config_str, &(an->config), an->signal_groups);
		*an_ptr = an;
		return SR_OK;
	}
}

int analyzer_run(struct sr_scpi_dev_inst *conn, const struct analyzer* an) {
	// Drain the storage_mem_data fifo
	uint16_t x = 0;
	assert(eb_csr_write_uint16_t(conn, an->csrs, "analyzer_storage_offset", x) == SR_OK);
	assert(eb_csr_write_uint16_t(conn, an->csrs, "analyzer_storage_length", x) == SR_OK);
	assert(eb_csr_write_bool(conn, an->csrs, "analyzer_storage_run", true) == SR_OK);
	return SR_OK;
}

bool analyzer_check(struct sr_scpi_dev_inst *conn, const struct analyzer* an) {
	bool r;
	assert(eb_csr_read_bool(conn, an->csrs, "analyzer_storage_idle", &r) == SR_OK);
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
		uint16_t temp_data = 0;
		eb_csr_read_uint16_t(conn, an->csrs, "analyzer_storage_mem_data", &temp_data);
		eb_csr_write_bool(conn, an->csrs, "analyzer_storage_mem_ready", true);
	}
	return SR_OK;
}
