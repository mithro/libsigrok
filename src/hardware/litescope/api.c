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

#include <assert.h>
#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <linux/limits.h>

#include "scpi.h"
#include "protocol.h"

#include "csr.h"
#include "analyzer.h"

#define LOG_PREFIX "litescope"

#define BUFSIZE (16 * 1024)

static struct sr_dev_driver litescope_driver_info;

static const char* CSR_FILE = "csr.csv";
static const char* ANALYZER_FILE = "analyzer.csv";

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
	SR_CONF_CONFIGDIR,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
//	/**
//	 * Channel configuration.
//	 * @arg type: string
//	 * @arg get: get current setting
//	 * @arg set: change current setting
//	 * @arg list: array of possible values
//	 */
//	SR_CONF_CHANNEL_CONFIG,
//
//
//	/** The device has internal storage, into which data is logged. This
//	 * starts or stops the internal logging. */
//	SR_CONF_DATALOG,
//
	SR_CONF_LIMIT_SAMPLES | SR_CONF_SET,
//	/**
//	 * Enabling/disabling channel.
//	 * @arg type: boolean
//	 * @arg get: @b true if currently enabled
//	 * @arg set: enable/disable
//	 */
//	SR_CONF_ENABLED,

//	{SR_CONF_CAPTURE_RATIO, SR_T_UINT64, "captureratio",
//		"Pre-trigger capture ratio", NULL},

//	{SR_CONF_BUFFERSIZE, SR_T_UINT64, "buffersize",
//		"Buffer size", NULL},

//	{SR_CONF_ENABLED, SR_T_BOOL, "enabled",
//		"Channel enabled", NULL},

//	{SR_CONF_LIMIT_SAMPLES, SR_T_UINT64, "limit_samples",
//		"Sample limit", NULL},

	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	/** The device supports setting a pre/post-trigger capture ratio. */
//	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
};

static const uint32_t devopts_cg[] = {
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
};

static struct analyzer* analyzer_read_config(const char* config_dir) {
	// construct the csr config file path
	char analyzer_file[PATH_MAX];
	strncpy(analyzer_file, config_dir, PATH_MAX);
	strcpy(analyzer_file+strlen(analyzer_file), ANALYZER_FILE);

	sr_dbg("litescope::analyzer_read_config %s\n", analyzer_file);

	// Parse the analyzer.csv file
	struct analyzer *analyzer = NULL;
	if(analyzer_parse_file(analyzer_file, &analyzer) != SR_OK)
		goto err;
	assert(analyzer != NULL);

	// construct the csr config file path
	char csr_file[PATH_MAX];
	strncpy(csr_file, config_dir, PATH_MAX);
	strcpy(csr_file+strlen(csr_file), CSR_FILE);

	sr_dbg("litescope::csr_read_config %s\n", csr_file);

	// Parse the csr.csv file into the analyzer table
	if(csr_parse_file(csr_file, &analyzer->csrs) != SR_OK)
		goto err;
	assert(analyzer->csrs != NULL);
	sr_info("litescope::csr_read_config %s with %d entries\n", csr_file, g_hash_table_size(analyzer->csrs));

//	sr_info("Device IP: %d.%d.%d.%d\n",
//		csr_get_constant(analyzer->csrs, "localip1"),
//		csr_get_constant(analyzer->csrs, "localip2"),
//		csr_get_constant(analyzer->csrs, "localip3"),
//		csr_get_constant(analyzer->csrs, "localip4"));

	return analyzer;
err:
	return NULL;
}

struct analyzer *global_analyzer = NULL;

#define BUF_SIZE 1023

static struct sr_dev_inst *probe_device(struct sr_scpi_dev_inst *scpi)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	//struct sr_scpi_hw_info *hw_info;

	sr_dbg("litescope::probe_device %p\n", scpi);

	sdi = NULL;
	devc = NULL;
	//hw_info = NULL;

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	assert(sdi != NULL);
	sdi->status = SR_ST_INACTIVE;
	sdi->vendor = g_strdup("LiteScope");
	sdi->model = g_strdup("Virtual Logic Analyzer");
	sdi->version = g_strdup("v1.0");
	sdi->driver = &litescope_driver_info;
	sdi->inst_type = SR_INST_SCPI;
	sdi->conn = scpi;

	for (GSList* iter = global_analyzer->channel_groups; iter; iter = g_slist_next(iter)) {
		struct sr_channel_group* cg = iter->data;
		assert(cg != NULL);
		assert(cg->name != NULL);
		assert(cg->channels != NULL);

		// Bind all the channels in the channel group to the sdi
		// object.
		for (GSList* jter = cg->channels; jter; jter = g_slist_next(jter)) {
			struct sr_channel* ch = jter->data;
			assert(ch != NULL);
			ch->sdi = sdi;
			sdi->channels = g_slist_append(sdi->channels, ch);
		}
		// Bind the channel group to the sdi object.
		sdi->channel_groups = g_slist_append(sdi->channel_groups, cg);
	}

	// Read the serial number from the device.
	sdi->serial_num = litescope_serial(sdi);

	devc = g_malloc0(sizeof(struct dev_context));

	// FIXME: Make sure this rounds up...
	devc->sample_width = ROUND_UP(global_analyzer->config.samples_bitwidth, 8);
	sr_spew("sample byte width %hu (bit width %d)", devc->sample_width, global_analyzer->config.samples_bitwidth);
	assert(devc->sample_width > 0);
	devc->samples_max = global_analyzer->config.samples_maxdepth;
	devc->trigger_mask = g_malloc0_n(sizeof(uint8_t), devc->sample_width);
	devc->trigger_mask[0] = 0xff;
	devc->trigger_mask[1] = 0xff;
	devc->trigger_value = g_malloc0_n(sizeof(uint8_t), devc->sample_width);
	devc->samples_data = g_malloc0_n(devc->sample_width, devc->samples_max);

	sdi->priv = devc;
	return sdi;
}

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	GSList *l;
	sr_dbg("litescope::scan\n");

	// Figure out the config dir
	const char *config_dir = NULL;
	for (l = options; l; l = l->next) {
		struct sr_config *src = l->data;
		switch (src->key) {
		case SR_CONF_CONFIGDIR: {
			config_dir = g_variant_get_string(src->data, NULL);
			sr_dbg("litescope::scan::config_dir %s\n", config_dir);
			break;
		}
		}
	}

	// Read in the analyzer config file
	struct analyzer* analyzer = analyzer_read_config(config_dir);
	assert(analyzer != NULL);
	assert(analyzer->config.samples_bitwidth > 0);
	assert(analyzer->config.samples_maxdepth > 0);
	assert(analyzer->config.cd_ratio > 0);
	assert(analyzer->csrs != NULL);
	assert(analyzer->channel_groups != NULL);
	global_analyzer = analyzer;

	return sr_scpi_scan(di->context, options, probe_device);
}

static int dev_open(struct sr_dev_inst *sdi)
{
	sr_dbg("litescope::dev_open\n");
	if (sr_scpi_open(sdi->conn) != SR_OK)
		return SR_ERR;
	if (!litescope_poke(sdi))
		return SR_ERR;
	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	sr_dbg("litescope::dev_close\n");
	return sr_scpi_close(sdi->conn);
}


static void log_key(const struct sr_dev_inst *sdi,
	const struct sr_channel_group *cg, uint32_t key, int op, GVariant *data)
{
	const char *opstr;
	const struct sr_key_info *srci;
	gchar *tmp_str = "";

	opstr = op == SR_CONF_GET ? "get" : op == SR_CONF_SET ? "set" : "list";
	srci = sr_key_info_get(SR_KEY_CONFIG, key);

	if (data != NULL) {
		tmp_str = g_variant_print(data, TRUE);
	}
	sr_spew("sr_config_%s(): key %x (%s) sdi %p cg %s -> %s", opstr, key,
		srci ? srci->id : "NULL", sdi, cg ? cg->name : "NULL",
		data ? tmp_str : "NULL");
	if (data != NULL) {
		g_free(tmp_str);
	}
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	sr_dbg("litescope::config_get key:%x data:%p sdi:%p cg:%s\n",
		key, *data, sdi, cg->name);

	log_key(sdi, cg, key, SR_CONF_GET, *data);

	ret = SR_OK;
	switch (key) {
	case SR_CONF_TRIGGER_MATCH:
	{
		break;
	}
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	sr_dbg("litescope::config_set key:%x data:%p sdi:%p cg:%s\n",
		key, data, sdi, cg != NULL ? cg->name : "(nil)");

	log_key(sdi, cg, key, SR_CONF_SET, data);

	ret = SR_OK;
	switch (key) {
	case SR_CONF_TRIGGER_MATCH:
		break;
	case SR_CONF_LIMIT_SAMPLES:
		break;
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_channel_set(const struct sr_dev_inst *sdi,
	struct sr_channel *ch, unsigned int changes)
{
	assert(sdi != NULL);
	assert(ch != NULL);
	sr_dbg("litescope::config_channel_set sdi:%p ch:%s\n",
		sdi, ch != NULL ? ch->name : "(nil)");

	/* Currently we only handle SR_CHANNEL_SET_ENABLED. */
	if (changes != SR_CHANNEL_SET_ENABLED)
		return SR_ERR_NA;

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	sr_dbg("litescope::config_list 1 key:%x data:%p sdi:%p cg:%s\n",
		key, *data, sdi, cg != NULL ? cg->name : "(nil)");
	log_key(sdi, cg, key, SR_CONF_LIST, NULL);

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
		sr_dbg("litescope::config_list 2 SR_CONF_SCAN_OPTIONS %p\n", cg);
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, NULL, NULL);

	case SR_CONF_DEVICE_OPTIONS:
		sr_dbg("litescope::config_list 2 SR_CONF_DEVICE_OPTIONS %p\n", cg);
		if (!cg)
			return STD_CONFIG_LIST(key, data, sdi, cg, NULL, drvopts, devopts);
		*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg));
		break;

	case SR_CONF_TRIGGER_MATCH:
		*data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
		break;

	/* TODO */
	default:
		sr_dbg("litescope::config_list 2 ??? %x\n", key);
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	assert(sdi != NULL);
	struct dev_context *devc;
	devc = sdi->priv;
	assert(devc != NULL);
	struct sr_scpi_dev_inst *scpi;
	scpi = sdi->conn;
	assert(scpi != NULL);

	devc->state = LITESCOPE_STATE_INIT;
	while(!litescope_setup(sdi));

	sr_scpi_source_add(
		sdi->session, scpi, G_IO_IN, 50,
		litescope_receive_data, (void *)sdi);

	std_session_send_df_header(sdi);

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	struct sr_scpi_dev_inst *scpi;
	struct dev_context *devc;

	std_session_send_df_end(sdi);

	devc = sdi->priv;
	scpi = sdi->conn;
	sr_scpi_source_remove(sdi->session, scpi);

	return SR_OK;
}

static struct sr_dev_driver litescope_driver_info = {
	.name = "litescope",
	.longname = "LiteScope - Virtual FPGA Scope",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_channel_set = config_channel_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(litescope_driver_info);
