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

#ifndef LIBSIGROK_HARDWARE_LITESCOPE_PROTOCOL_H
#define LIBSIGROK_HARDWARE_LITESCOPE_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "litescope"

enum litescope_state {
	LITESCOPE_STATE_INIT,
	LITESCOPE_STATE_WRITE_TRIGGER_MASK,
	LITESCOPE_STATE_WRITE_TRIGGER_VALUE,
	LITESCOPE_STATE_FLUSHING,
	LITESCOPE_STATE_WRITE_TRIGGER_OFFSET,
	LITESCOPE_STATE_WRITE_LENGTH,
	LITESCOPE_STATE_WRITE_RUN,
	LITESCOPE_STATE_WAITING, // Waiting on the device to indicate it has triggered
	LITESCOPE_STATE_READING, // Data is being read out of the memory
	LITESCOPE_STATE_NOTIFY,  // Sending the data to sigrok
	LITESCOPE_STATE_COMPLETE,
};

struct dev_context {
	enum litescope_state state;

	size_t sample_width;		// How many bytes each sample takes

	uint8_t *trigger_mask;
	uint8_t *trigger_value;
	uint16_t trigger_at;		// Where the trigger point will be

	uint16_t samples_max;		// Max number of samples
	size_t samples_current;		// Current number of samples
	uint8_t *samples_data;		// Actual sample data

	struct etherbone_packet* request;
	struct etherbone_packet* response;
};

SR_PRIV char* litescope_serial(struct sr_dev_inst *sdi);
SR_PRIV bool litescope_poke(struct sr_dev_inst *sdi);
SR_PRIV bool litescope_setup(struct sr_dev_inst *sdi);
SR_PRIV bool litescope_poll(struct sr_dev_inst *sdi);

SR_PRIV int litescope_receive_data(int fd, int revents, void *cb_data);

#endif
