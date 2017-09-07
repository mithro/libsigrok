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
//	/** The device supports setting a pre/post-trigger capture ratio. */
//	SR_CONF_CAPTURE_RATIO,
//
//	/** The device supports run-length encoding (RLE). */
//	SR_CONF_RLE,
//
//	/** Trigger source. */
//	SR_CONF_TRIGGER_SOURCE,
//	/**
//	 * Enabling/disabling channel.
//	 * @arg type: boolean
//	 * @arg get: @b true if currently enabled
//	 * @arg set: enable/disable
//	 */
//	SR_CONF_ENABLED,
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
//
//
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_PATTERN_MODE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_EXTERNAL_CLOCK | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SWAP | SR_CONF_SET,
	SR_CONF_RLE | SR_CONF_GET | SR_CONF_SET,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
	SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING,
};

// 
//

static struct analyzer* analyzer_read_config(const char* config_dir) {
	// construct the csr config file path
	char analyzer_file[PATH_MAX];
	strncpy(analyzer_file, config_dir, PATH_MAX);
	strcpy(analyzer_file+strlen(analyzer_file), ANALYZER_FILE);

	sr_dbg("litescope::analyzer_read_config %s\n", analyzer_file);

	// Parse the analyzer.csv file
	struct analyzer *analyzer;
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

	sr_info("Device IP: %d.%d.%d.%d\n",
		csr_get_constant(analyzer->csrs, "localip1"),
		csr_get_constant(analyzer->csrs, "localip2"),
		csr_get_constant(analyzer->csrs, "localip3"),
		csr_get_constant(analyzer->csrs, "localip4"));

	return analyzer;
err:
	if (analyzer != NULL) {
		if (analyzer->csrs != NULL) {
			g_hash_table_destroy(analyzer->csrs);
		}
		if (analyzer->signals != NULL) {
			g_hash_table_destroy(analyzer->signals);
		}
		g_free(analyzer);
	}
	return NULL;
}

static struct analyzer *global_analyzer = NULL;

static struct sr_dev_inst *probe_device(struct sr_scpi_dev_inst *scpi)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	//struct sr_scpi_hw_info *hw_info;

	sr_dbg("litescope::probe_device %p\n", scpi);

	// info_dna_id
	uint64_t dna_id = (uint64_t)-1;
	assert(global_analyzer != NULL);
	if(eb_csr_read_uint64_t(scpi, global_analyzer->csrs, "info_dna_id", &dna_id) != SR_OK) {
		return NULL;
	}
	assert(dna_id != (uint64_t)-1);
	sr_info("Device DNA: 0x%" PRIx64 "\n", dna_id);

	// Write 0x000f to the trigger
	uint16_t trigger_value = 0xf;
	if(eb_csr_write_uint16_t(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", trigger_value) != SR_OK) {
		sr_err("1 - write to analyzer_frontend_trigger_value failed.");
		return NULL;
	}
	trigger_value = 0;
	if(eb_csr_read_uint16_t(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", &trigger_value) != SR_OK) {
		sr_err("2 - read to analyzer_frontend_trigger_value failed.");
		return NULL;
	}
	sr_spew("analyzer_frontend_trigger_value: %hx (should be 0x000f)", trigger_value);
	assert(trigger_value == 0xf);

	// Write 0xf000 to the trigger
	trigger_value = 0xf000;
	if(eb_csr_write_uint16_t(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", trigger_value) != SR_OK) {
		sr_err("3 - write to analyzer_frontend_trigger_value failed.");
		return NULL;
	}
	trigger_value = 0;
	if(eb_csr_read_uint16_t(scpi, global_analyzer->csrs, "analyzer_frontend_trigger_value", &trigger_value) != SR_OK) {
		sr_err("4 - read to analyzer_frontend_trigger_value failed.");
		return NULL;
	}
	sr_spew("analyzer_frontend_trigger_value: %hx (should be 0xf000)", trigger_value);
	assert(trigger_value == 0xf000);

	sdi = NULL;
	devc = NULL;
	//hw_info = NULL;

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	devc = g_malloc0(sizeof(struct dev_context));
	sdi->priv = devc;
	return sdi;

//	return NULL;
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
		case SR_CONF_CONFIGDIR:
			config_dir = g_variant_get_string(src->data, NULL);
			sr_dbg("litescope::scan::config_dir %s\n", config_dir);
			break;
		}
	}

	// Read in the analyzer config file
	struct analyzer* analyzer = analyzer_read_config(config_dir);
	assert(analyzer != NULL);
	assert(analyzer->signals != NULL);
	assert(analyzer->csrs != NULL);
	global_analyzer = analyzer;

	return sr_scpi_scan(di->context, options, probe_device);
//	
//
//	struct drv_context *drvc;
//	GSList *devices;
//
//	(void)options;
//
//	devices = NULL;
//	drvc = di->context;
//	drvc->instances = NULL;
//
//	/* TODO: scan for devices, either based on a SR_CONF_CONN option
//	 * or on a USB scan. */
//
//	return devices;
}

static int dev_open(struct sr_dev_inst *sdi)
{
	(void)sdi;

	sr_dbg("litescope::dev_open\n");
	/* TODO: get handle from sdi->conn and open it. */

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	sr_dbg("litescope::dev_close\n");
	/* TODO: get handle from sdi->conn and close it. */

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	sr_dbg("litescope::config_get\n");
	ret = SR_OK;
	switch (key) {
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

	(void)sdi;
	(void)data;
	(void)cg;

	sr_dbg("litescope::config_set\n");
	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	sr_dbg("litescope::config_list\n");
	ret = SR_OK;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
		sr_dbg("litescope::config_list SR_CONF_SCAN_OPTIONS %p\n", cg);
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, NULL, NULL);

	case SR_CONF_DEVICE_OPTIONS:
		sr_dbg("litescope::config_list SR_CONF_DEVICE_OPTIONS %p\n", cg);
		if (!cg)
			return STD_CONFIG_LIST(key, data, sdi, cg, NULL, drvopts, devopts);
		//*data = std_gvar_array_u32(ARRAY_AND_SIZE(devopts_cg_analog));
		break;

	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	(void)sdi;

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	/* TODO: stop acquisition. */

	(void)sdi;

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
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(litescope_driver_info);
