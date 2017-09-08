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
#include "protocol.h"

SR_PRIV int litescope_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents == G_IO_IN) {
		/* TODO */
	}

	return TRUE;
}

//
//	/*
//	 * Send "frame begin" packet upon reception of data for the
//	 * first enabled channel.
//	 */
//	if (devc->current_channel == devc->enabled_channels) {
//		packet.type = SR_DF_FRAME_BEGIN;
//		sr_session_send(sdi, &packet);
//	}
//
//	if (ch->type != SR_CHANNEL_ANALOG)
//		return SR_ERR;
//
//	/* Pass on the received data of the channel(s). */
//	if (sr_scpi_read_data(sdi->conn, buf, 4) != 4) {
//		sr_err("Reading header failed.");
//		return TRUE;
//	}
//
//	if (sr_scpi_get_block(sdi->conn, NULL, &data) != SR_OK) {
//		if (data)
//			g_byte_array_free(data, TRUE);
//		return TRUE;
//	}
//
//	analog.encoding = &encoding;
//	analog.meaning = &meaning;
//	analog.spec = &spec;
//
//	if (lecroy_waveform_to_analog(data, &analog) != SR_OK)
//		return SR_ERR;
//
//	meaning.channels = g_slist_append(NULL, ch);
//	packet.payload = &analog;
//	packet.type = SR_DF_ANALOG;
//	sr_session_send(sdi, &packet);
//
//	g_byte_array_free(data, TRUE);
//	data = NULL;
//
//	g_slist_free(meaning.channels);
//	g_free(analog.data);
//
//	/*
//	 * Advance to the next enabled channel. When data for all enabled
//	 * channels was received, then flush potentially queued logic data,
//	 * and send the "frame end" packet.
//	 */
//	if (devc->current_channel->next) {
//		devc->current_channel = devc->current_channel->next;
//		lecroy_xstream_request_data(sdi);
//		return TRUE;
//	}
//
//	packet.type = SR_DF_FRAME_END;
//	sr_session_send(sdi, &packet);
//
//	/*
//	 * End of frame was reached. Stop acquisition after the specified
//	 * number of frames, or continue reception by starting over at
//	 * the first enabled channel.
//	 */
//	if (++devc->num_frames == devc->frame_limit) {
//		sr_dev_acquisition_stop(sdi);
//	} else {
//		devc->current_channel = devc->enabled_channels;
//		lecroy_xstream_request_data(sdi);
//	}
//
//
