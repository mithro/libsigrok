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

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#include "simple-csv.h"

#define LOG_PREFIX "litescope/csv"

int csv_parse_file(const char* filename, csv_parse_line_t parse_line_callback, void* private_data) {
	int r = SR_ERR;
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

		if(!parse_line_callback(token, private_data)) {
			goto err;
		}
	}

	r = SR_OK;
err:
	if (stream != NULL) {
		fclose(stream);
	}
	if (data != NULL) {
		g_string_free(data, TRUE);
	}
	return r;
}
