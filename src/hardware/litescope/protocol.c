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
#include <unistd.h>

#include "scpi.h"

#include "easy-eb.h"
#include "analyzer.h"

#include "protocol.h"

extern struct analyzer *global_analyzer;

SR_PRIV char* litescope_serial(struct sr_dev_inst *sdi) {
	assert(sdi != NULL);
	struct sr_scpi_dev_inst *scpi;
	scpi = sdi->conn;
	assert(scpi != NULL);

	assert(global_analyzer != NULL);

	// info_dna_id
	uint64_t dna_id = (uint64_t)-1;
	if(eb_csr_read_uint64_t(scpi, global_analyzer->csrs, "info_dna_id", &dna_id) != SR_OK) {
		return false;;
	}
	assert(dna_id != (uint64_t)-1);
	char dna_str[64] = {0};
	snprintf(dna_str, 63, "0x%" PRIx64, dna_id);
	sr_info("Device DNA: 0x%s\n", dna_str);
	return g_strdup(dna_str);
}

SR_PRIV bool litescope_poke(struct sr_dev_inst *sdi) {
	assert(sdi != NULL);
	struct dev_context *devc;
	devc = sdi->priv;
	assert(devc != NULL);
	struct sr_scpi_dev_inst *scpi;
	scpi = sdi->conn;
	assert(scpi != NULL);

	assert(global_analyzer != NULL);

	free(litescope_serial(sdi));

	// Write 0x000f to the trigger
	sr_spew("Sample width bytes: %d\n", devc->sample_width);
	devc->trigger_value[devc->sample_width-1] = 0xf;
	if(eb_csr_write_bytes(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", devc->trigger_value, devc->sample_width) != SR_OK) {
		sr_err("1 - write to analyzer_frontend_trigger_value failed.");
		return false;;
	}
	for (size_t i = 0; i < devc->sample_width; i++) {
		devc->trigger_value[i] = 0;
	}
	if(eb_csr_read_bytes(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", &(devc->trigger_value[0]), devc->sample_width) != SR_OK) {
		sr_err("2 - read to analyzer_frontend_trigger_value failed.");
		return false;;
	}
	sr_spew("analyzer_frontend_trigger_value: %hhx (should be 0x0f)", devc->trigger_value[devc->sample_width-1]);
	assert(devc->trigger_value[devc->sample_width-1] == 0xf);

	// Write 0xf000 to the trigger
	devc->trigger_value[0] = 0xf0;
	if(eb_csr_write_bytes(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", devc->trigger_value, devc->sample_width) != SR_OK) {
		sr_err("3 - write to analyzer_frontend_trigger_value failed.");
		return false;;
	}
	for (size_t i = 0; i < devc->sample_width; i++) {
		devc->trigger_value[i] = 0;
	}
	if(eb_csr_read_bytes(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", &(devc->trigger_value[0]), devc->sample_width) != SR_OK) {
		sr_err("4 - read to analyzer_frontend_trigger_value failed.");
		return false;;
	}
	sr_spew("analyzer_frontend_trigger_value: %hhx (should be 0xf0)", devc->trigger_value[0]);
	//assert(devc->trigger_value[0] == 0xf0);
	return true;
}


void sr_spew_bytes(const char* s, uint8_t* bytes, size_t bytes_len);
void sr_spew_bytes(const char* s, uint8_t* bytes, size_t bytes_len) {
	sr_spew("%s", s);
	for (size_t i = 0; i < bytes_len; i++) {
		sr_spew("%hhx ", bytes[i]);
	}
}

SR_PRIV bool litescope_setup(struct sr_dev_inst *sdi) {
	assert(sdi != NULL);
	struct dev_context *devc;
	devc = sdi->priv;
	assert(devc != NULL);
	struct sr_scpi_dev_inst *scpi;
	scpi = sdi->conn;
	assert(scpi != NULL);

	switch(devc->state) {
	case LITESCOPE_STATE_INIT:
	{
		devc->trigger_at = 0;
		devc->samples_current = 0;
		devc->request = NULL;
		devc->response = NULL;
		devc->state++;
		break;
	}

	// Write the trigger mask
	case LITESCOPE_STATE_WRITE_TRIGGER_MASK:
	{
		sr_spew_bytes("Writing trigger mask:", devc->trigger_mask, devc->sample_width);
		if (eb_csr_write_bytes(
				scpi,
				global_analyzer->csrs, "analyzer_frontend_trigger_mask",
				devc->trigger_mask,
				devc->sample_width) != SR_OK) {
			return SR_ERR;
		}
		devc->state++;
		break;
	}

	// Write the trigger value
	case LITESCOPE_STATE_WRITE_TRIGGER_VALUE:
	{
		sr_spew_bytes("Writing trigger value:", devc->trigger_value, devc->sample_width);
		if (eb_csr_write_bytes(
				scpi,
				global_analyzer->csrs, "analyzer_frontend_trigger_value",
				devc->trigger_value,
				devc->sample_width) != SR_OK) {
			return SR_ERR;
		}
		devc->state++;
		break;
	}

	// Flush the storage
	case LITESCOPE_STATE_FLUSHING:
	{
		sr_spew("Flushing storage\n");
		while (true) {
			bool valid = false;
			if (eb_csr_read_bool(
					scpi,
					global_analyzer->csrs, "analyzer_storage_mem_valid",
					&valid) != SR_OK) {
				return SR_ERR;
			}
			sr_spew("Read storage_mem_valid of %xu\n", (unsigned)valid);
			if (!valid) {
				break;
			}
			if (eb_csr_write_bool(
					scpi,
					global_analyzer->csrs, "analyzer_storage_mem_ready",
					true) != SR_OK) {
				return SR_ERR;
			}
		}
		devc->state++;
		break;
	}

	// Write the trigger offset
	case LITESCOPE_STATE_WRITE_TRIGGER_OFFSET:
	{
		uint16_t trigger_at = devc->trigger_at > 0 ? devc->trigger_at : 0;
		sr_spew("Writing trigger offset: %hu\n", trigger_at);
		if (eb_csr_write_uint16_t(
				scpi,
				global_analyzer->csrs, "analyzer_storage_offset",
				trigger_at) != SR_OK) {
			return SR_ERR;
		}
		devc->state++;
		break;
	}

	// Write the sample length
	case LITESCOPE_STATE_WRITE_LENGTH:
	{
		sr_spew("Writing length: %hu\n", devc->samples_max);
		if (eb_csr_write_uint16_t(
				scpi,
				global_analyzer->csrs, "analyzer_storage_length",
				devc->samples_max) != SR_OK) {
			return SR_ERR;
		}
		devc->state++;
		break;
	}

	// Write the "go" value
	case LITESCOPE_STATE_WRITE_RUN:
	{
		sr_spew("Writing run\n");
		if (eb_csr_write_bool(
				scpi,
				global_analyzer->csrs, "analyzer_storage_start",
				true) != SR_OK) {
			return SR_ERR;
		}
		devc->state++;
		break;
	}

	default:
		sr_spew("Invalid state in litescope_setup.");
		assert(false);
	}
	return devc->state >= LITESCOPE_STATE_WAITING;
}

SR_PRIV bool litescope_poll(struct sr_dev_inst *sdi) {
	assert(sdi != NULL);
	struct dev_context *devc;
	devc = sdi->priv;
	assert(devc != NULL);
	struct sr_scpi_dev_inst *scpi;
	scpi = sdi->conn;
	assert(scpi != NULL);

	switch(devc->state) {
	// Wait for the trigger
	case LITESCOPE_STATE_WAITING:
	{
		sr_spew("Waiting for trigger\n");
		bool triggered = false;
		while (!triggered) {
			if (eb_csr_read_bool(
					scpi,
					global_analyzer->csrs, "analyzer_storage_idle",
					&triggered) != SR_OK) {
				return SR_ERR;
			}
			sr_spew("Read trigger of %xu\n", (unsigned)triggered);
			if (!triggered) {
				sleep(1);
			}
		}
		devc->state++;
		break;
	}

	// Read the run value
	case LITESCOPE_STATE_READING:
	{
		sr_spew("Reading sample data out of litescope\n");
		while(devc->samples_current < devc->samples_max) {
			// FIXME: Should I read something here?

			sr_spew("Reading sample: %lu (of %lu)\n", devc->samples_current, devc->samples_max);
			uint8_t *dst_ptr = (
				devc->samples_data +
				(devc->samples_current * devc->sample_width));
			size_t dst_ptr_width = devc->sample_width;
			if (eb_csr_read_bytes(
					scpi,
					global_analyzer->csrs, "analyzer_storage_mem_data",
					dst_ptr, dst_ptr_width) != SR_OK) {
				return SR_ERR;
			}
			sr_spew("Got samples:");
			for (size_t i = 0; i < dst_ptr_width; i++) {
				sr_spew("%hhx", devc->samples_data[devc->samples_current+i]);
			}
			sr_spew("\n");

			if (eb_csr_write_bool(
					scpi,
					global_analyzer->csrs, "analyzer_storage_mem_ready",
					true) != SR_OK) {
				return SR_ERR;
			}

			devc->samples_current++;
		}
		devc->state++;
		break;
	}

	case LITESCOPE_STATE_NOTIFY:
	{
		sr_spew("Sending sigrok notify\n");
		struct sr_datafeed_packet packet;
		struct sr_datafeed_logic logic;

		packet.type = SR_DF_LOGIC;
		packet.payload = &logic;
		logic.length = devc->samples_current * devc->sample_width;
		logic.unitsize = devc->sample_width;
		logic.data = devc->samples_data;

		sr_session_send(sdi, &packet);

		sr_dev_acquisition_stop(sdi);

		devc->state++;
		break;
	}

	default:
		sr_spew("Invalid state in litescope_run.");
		assert(false);
	}
	return devc->state >= LITESCOPE_STATE_COMPLETE;
}


SR_PRIV int litescope_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	while(!litescope_poll(sdi));

	return TRUE;
}
