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

int analyzer_parse_file(const char* filename, GHashTable** csr_table_ptr);
bool analyzer_parse_line(char* line, GHashTable* csr_table_ptr);

#endif
