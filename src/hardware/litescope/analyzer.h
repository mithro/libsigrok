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

#ifndef LIBSIGROK_HARDWARE_LITESCOPE_ANALYZER_H
#define LIBSIGROK_HARDWARE_LITESCOPE_ANALYZER_H

#include <config.h>

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

struct analyzer_signal {
	int group;
	char* name;
	int bits;
};

struct analyzer_config {
	int data_width;
	int data_depth;
	int cd_ratio;
	int num_groups;
};

struct analyzer {
	struct analyzer_config config;
	GHashTable* csrs;
	GHashTable* signals;
};

int analyzer_parse_file(const char* filename, struct analyzer** an_ptr);
bool analyzer_parse_line(char* line, struct analyzer* an);

char* analyzer_signal_str(const struct analyzer_signal* signal);
char* analyzer_config_str(const struct analyzer_config* config);

#define sr_analyzer_log(LEVEL, func, value) \
	do { \
		char* msg = func(value); \
		sr_ ## LEVEL ("%s\n", msg); \
		g_free(msg); \
	} while(false)

#endif
