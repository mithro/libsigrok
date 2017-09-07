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

#ifndef LIBSIGROK_HARDWARE_LITESCOPE_SIMPLE_CSV_H
#define LIBSIGROK_HARDWARE_LITESCOPE_SIMPLE_CSV_H

#include <config.h>

#include <stdbool.h>

typedef bool (*csv_parse_line_t)(char* line, void* private_data);
int csv_parse_file(const char* filename, csv_parse_line_t parse_line_callback, void* private_data);

#endif
