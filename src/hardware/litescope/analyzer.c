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

char* analyzer_channel_str(const struct sr_channel* ch, size_t channel_group) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(ch);

	snprintf(buf, BUF_SIZE, "signal%zd@%p(%s, %d)\n",
		 channel_group, ch, ch->name, ch->index);
	return g_strndup(buf, BUF_SIZE);
}

char* analyzer_config_str(const struct analyzer_config* config, size_t channel_groups) {
	char buf[BUF_SIZE+1];
	buf[BUF_SIZE] = '\0';

	assert(config);

	snprintf(buf, BUF_SIZE, "config@%p(width:%d, depth:%d, cd_ratio:%d, groups:%zd)\n",
		 config,
		 config->samples_bitwidth, config->samples_maxdepth,
		 config->cd_ratio,
		 channel_groups);
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
			sscanf(value, "%d", &((*an_ptr)->config.samples_bitwidth));
		} else if (strcmp(name, "depth") == 0) {
			sscanf(value, "%d", &((*an_ptr)->config.samples_maxdepth));
		} else if (strcmp(name, "cd_ratio") == 0) {
			sscanf(value, "%d", &((*an_ptr)->config.cd_ratio));
		} else {
			sr_err("Invalid config value '%s' in column 0 in line %zu.",
				name, (size_t)0);
			return false;
		}
	} else if (strcmp(type, "signal") == 0) {

		char temp_buf[BUF_SIZE] = {0};
		struct sr_channel_group* cg = NULL;

		size_t group_num = 0;
		sscanf(group, "%zd", &group_num);
		while(group_num >= g_slist_length((*an_ptr)->channel_groups)) {
			cg = g_malloc0(sizeof(struct sr_channel_group));
			assert(cg != NULL);

			snprintf(temp_buf, BUF_SIZE,
				 "Group %d", g_slist_length((*an_ptr)->channel_groups));

			cg->name = g_strdup(temp_buf);
			(*an_ptr)->channel_groups = g_slist_append((*an_ptr)->channel_groups, cg);
		}

		cg = g_slist_nth_data((*an_ptr)->channel_groups, group_num);
		assert(cg != NULL);

		size_t bits = 0;
		sscanf(value, "%zd", &bits);
		assert(bits > 0);
		for (size_t i = 0; i < bits; i++) {
			struct sr_channel* ch = g_malloc0(sizeof(struct sr_channel));
			assert(ch != NULL);

			ch->index = g_slist_length(cg->channels);
			ch->type = SR_CHANNEL_LOGIC;
			ch->enabled = group_num == 0;

			if (bits > 1) {
				snprintf(temp_buf, BUF_SIZE, "%s[%zd]", name, i);
			} else {
				snprintf(temp_buf, BUF_SIZE, "%s", name);
			}
			ch->name = g_strdup(temp_buf);

			cg->channels = g_slist_append(cg->channels, ch);
		}
	} else {
		sr_err("Invalid config value '%s' in column 0 in line %zu.",
			type, (size_t)0);
		return false;
	}
	return true;
}


char* sr_channel_group_prefix(struct sr_channel_group* cg);
char* sr_channel_group_prefix(struct sr_channel_group* cg) {
	assert(cg != NULL);
	assert(cg->channels != NULL);

	const char *prefix_str = NULL;
	size_t prefix_str_pos = (size_t)-1;

	for (GSList* iter = cg->channels; iter; iter = g_slist_next(iter)) {
		struct sr_channel* ch = iter->data;
		assert(ch != NULL);
		assert(ch->name != NULL);
		assert(strlen(ch->name) > 0);

		if (prefix_str == NULL) {
			prefix_str = ch->name;
		}

		size_t prefix_cur = 0;
		while(((prefix_cur < strlen(prefix_str)) && (prefix_cur < strlen(ch->name))) &&
				prefix_str[prefix_cur] == ch->name[prefix_cur] &&
				prefix_str[prefix_cur] != '[') {
			prefix_cur++;
		}
		sr_spew("prefix:%s[%zd] (%s %s)\n", g_strndup(ch->name, prefix_cur), prefix_cur, ch->name, prefix_str);
		if (prefix_cur < prefix_str_pos) {
			prefix_str_pos = prefix_cur;
		}
	}
	assert(prefix_str != NULL);
	assert(prefix_str_pos != (size_t)-1);
	return g_strndup(prefix_str, prefix_str_pos);
}


int analyzer_parse_file(const char* filename, struct analyzer** an_ptr) {
	assert(an_ptr != NULL);
	assert(*an_ptr == NULL);

	struct analyzer* an = g_malloc0(sizeof(struct analyzer));
	if (csv_parse_file(filename, (csv_parse_line_t)(&analyzer_parse_line), (void*)&an) != SR_OK) {
		//analyzer_free(&an);
		return SR_ERR;
	} else {
		assert(an != NULL);

		// Give the channel groups names
		for (GSList* iter = an->channel_groups; iter; iter = g_slist_next(iter)) {

			struct sr_channel_group* cg = iter->data;
			assert(cg != NULL);

			// Try and find a common prefix to all the channels in a group
			char* prefix = sr_channel_group_prefix(cg);
			size_t prefix_len = strlen(prefix);

			// Did we find a prefix?
			char temp_buf[BUF_SIZE+1];
			temp_buf[BUF_SIZE] = '\0';
			if (prefix_len > 0) {
				snprintf(temp_buf, BUF_SIZE, "Group %s", prefix);
				// Strip trailing characters
				while(temp_buf[strlen(temp_buf)-1] == '_') {
					temp_buf[strlen(temp_buf)-1] = '\0';
				}
				cg->name = g_strdup(temp_buf);

				// Strip the prefix from all the channel names.
				for (GSList* jter = cg->channels; jter; jter = g_slist_next(jter)) {
					struct sr_channel* ch = jter->data;
					assert(ch != NULL);
					assert(ch->name != NULL);
					assert(strlen(ch->name) > prefix_len);
					snprintf(temp_buf, BUF_SIZE, "%s", ch->name+prefix_len);
					g_free(ch->name);
					ch->name = g_strdup(temp_buf);
				}

			// Resort to just using the "Group <index>"
			} else {
				snprintf(temp_buf, BUF_SIZE, "Group %d",
					g_slist_position(an->channel_groups, iter));
				cg->name = g_strdup(temp_buf);
			}
		}

		sr_analyzer_log(spew, analyzer_config_str, &(an->config), g_slist_length(an->channel_groups));
		*an_ptr = an;
		return SR_OK;
	}
}
