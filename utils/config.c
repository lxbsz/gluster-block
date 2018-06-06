/*
  Copyright (c) 2018 Red Hat, Inc. <http://www.redhat.com>
  This file is part of gluster-block.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <pthread.h>

#include "utils.h"

typedef enum {
	GB_OPT_NONE = 0,
	GB_OPT_INT, /* type int */
	GB_OPT_STR, /* type string */
	GB_OPT_BOOL, /* type boolean */
	GB_OPT_MAX,
} gb_option_type;

struct gb_conf_option {
	struct list_head list;

	char *key;
	gb_option_type type;
	union {
		int opt_int;
		bool opt_bool;
		char *opt_str;
	};
};

/*
 * System config for gluster-block, for now there are only 3 option types supported:
 * 1, The "int type" option, for example:
 *	gb_int = 2
 *
 * 2, The "string type" option, for example:
 *	gb_str = "Tom"  --> Tom
 *    or
 *	gb_str = 'Tom'  --> Tom
 *    or
 *	gb_str = 'Tom is a "boy"' ---> Tom is a "boy"
 *    or
 *	gb_str = "'T' is short for Tom" --> 'T' is short for Tom
 *
 * 3, The "boolean type" option, for example:
 *	gb_bool
 *
 * ========================
 * How to add new options ?
 *
 * Using "GB_LOG_LEVEL" as an example:
 *
 * 1, Add logLevel member in:
 *	struct gb_config {
 *		char *logLevel;
 *	};
 *    in file utils.h.
 *
 * 2, Add the following option in "gluster-blockd" file as default:
 *	GB_LOG_LEVEL=INFO
 *    or
 *	GB_LOG_LEVEL = INFO
 *
 *    Note: the option name in config file must be the same as in
 *    gb_config.
 *
 * 3, You should add your own set method in:
 *	static void glusterBlockConfSetOptions(struct gb_config *cfg)
 *	{
 *		GB_PARSE_CFG_STR(cfg, logLevel);
 *	}
 * 4, Then add your own free method in if it's a STR KEY:
 *	static void glusterBlockConfFreeStrKeys(struct gb_config *cfg)
 *	{
 *		GB_FREE_CFG_STR_KEY(cfg, 'STR KEY');
 *	}
 *
 * Note: For now, if the options have been changed in config file, the
 * system config reload thread daemon will try to update them for all the
 * gb-runner, consumer and gb-synthesizer daemons.
 */

static LIST_HEAD(gb_options);

static struct gb_conf_option * glusterBlockGetOption(const char *key)
{
	struct list_head *pos;
	struct gb_conf_option *option;

	list_for_each(pos, &gb_options) {
		option = list_entry(pos, struct gb_conf_option, list);
		if (!strcmp(option->key, key))
			return option;
	}

	return NULL;
}

/* The default value should be specified here,
 * so the next time when users comment out an
 * option in config file, here it will set the
 * default value back.
 */
#define GB_PARSE_CFG_INT(cfg, key, def) \
do { \
	struct gb_conf_option *option; \
	option = glusterBlockGetOption(#key); \
	if (option) { \
		cfg->key = option->opt_int; \
		option->opt_int = def; \
	} \
} while (0)

#define GB_PARSE_CFG_BOOL(cfg, key, def) \
do { \
	struct gb_conf_option *option; \
	option = glusterBlockGetOption(#key); \
	if (option) { \
		cfg->key = option->opt_bool; \
		option->opt_bool = def; \
	} \
} while (0)

#define GB_PARSE_CFG_STR(cfg, key, def) \
do { \
	struct gb_conf_option *option; \
	char buf[1024]; \
	option = glusterBlockGetOption(#key); \
	if (option) { \
		if (cfg->key) \
			free(cfg->key); \
		cfg->key = strdup(option->opt_str); \
		if (option->opt_str) \
			free(option->opt_str); \
		sprintf(buf, "%s", def); \
		option->opt_str = strdup(buf); \
	} \
} while (0);

#define GB_FREE_CFG_STR_KEY(cfg, key) \
do { \
	free(cfg->key); \
} while (0);

static void glusterBlockConfSetOptions(struct gb_config *cfg, bool reloading)
{
	unsigned int logLevel;

	/* set logLevel option */
	GB_PARSE_CFG_STR(cfg, GB_LOG_LEVEL, "INFO");
	if (cfg->GB_LOG_LEVEL) {
		logLevel = blockLogLevelEnumParse(cfg->GB_LOG_LEVEL);
		glusterBlockSetLogLevel(logLevel);
	}

	/* add your new config options */
}

static void glusterBlockConfFreeStrKeys(struct gb_config *cfg)
{
	/* add your str type config options
	 *
	 * For example:
	 * GB_FREE_CFG_STR_KEY(cfg, 'STR KEY');
	 */
}

#define GB_MAX_CFG_FILE_SIZE (2 * 1024 * 1024)
static int glusterBlockReadConfig(int fd, char *buf, int count)
{
	ssize_t len;
	int save = errno;

	do {
		len = read(fd, buf, count);
	} while (errno == EAGAIN);

	errno = save;
	return len;
}

/* end of line */
#define __EOL(c) (((c) == '\n') || ((c) == '\r'))

#define GB_TO_LINE_END(x, y) \
	do { while ((x) < (y) && !__EOL(*(x))) { \
		(x)++; } \
	} while (0);

/* skip blank lines */
#define GB_SKIP_BLANK_LINES(x, y) \
	do { while ((x) < (y) && (isblank(*(x)) || __EOL(*(x)))) { \
		(x)++; } \
	} while (0);

/* skip comment line with '#' */
#define GB_SKIP_COMMENT_LINE(x, y) \
	do { while ((x) < (y) && !__EOL(*x)) { \
		(x)++; } \
	     (x)++; \
	} while (0);

/* skip comment lines with '#' */
#define GB_SKIP_COMMENT_LINES(x, y) \
	do { while ((x) < (y) && *(x) == '#') { \
		GB_SKIP_COMMENT_LINE((x), (y)); } \
	} while (0);

#define MAX_KEY_LEN 64
#define MAX_VAL_STR_LEN 256

static struct gb_conf_option *
glusterBlockRegisterOption(char *key, gb_option_type type)
{
	struct gb_conf_option *option;

	option = calloc(1, sizeof(*option));
	if (!option)
		return NULL;

	option->key = strdup(key);
	if (!option->key)
		goto free_option;
	option->type = type;
	INIT_LIST_HEAD(&option->list);

	list_add_tail(&gb_options, &option->list);
	return option;

free_option:
	free(option);
	return NULL;
}

static void glusterBlockParseOption(char **cur, const char *end)
{
	struct gb_conf_option *option;
	gb_option_type type;
	char *p = *cur, *q = *cur, *r, *s;

	while (isblank(*p))
		p++;

	GB_TO_LINE_END(q, end);
	*q = '\0';
	*cur = q + 1;

	/* parse the boolean type option */
	s = r = strchr(p, '=');
	if (!r) {
		/* boolean type option at file end or line end */
		r = p;
		while (!isblank(*r) && r < q)
			r++;
		*r = '\0';
		option = glusterBlockGetOption(p);
		if (!option)
			option = glusterBlockRegisterOption(p, GB_OPT_BOOL);

		if (option)
			option->opt_bool = true;

		return;
	}
	/* skip character '='  */
	s++;
	r--;
	while (isblank(*r))
		r--;
	r++;
	*r = '\0';

	option = glusterBlockGetOption(p);
	if (!option) {
		r = s;
		while (isblank(*r))
			r++;
		LOG("general", GB_LOG_INFO, "option type s:'%s', r:'%s' not supported!\n", s, r);

		if (isdigit(*r))
			type = GB_OPT_INT;
		else
			type = GB_OPT_STR;

		option = glusterBlockRegisterOption(p, type);
		if (!option)
			return;
	}

	/* parse the int/string type options */
	switch (option->type) {
	case GB_OPT_INT:
		while (!isdigit(*s))
			s++;
		r = s;
		while (isdigit(*r))
			r++;
		*r= '\0';

		option->opt_int = atoi(s);
		break;
	case GB_OPT_STR:
	//	s++;
		while (isblank(*s))
			s++;
		/* skip first " or ' if exist */
		if (*s == '"' || *s == '\'')
			s++;
		r = q - 1;
		while (isblank(*r))
			r--;
		/* skip last " or ' if exist */
		if (*r == '"' || *r == '\'')
			*r = '\0';

		if (option->opt_str)
			/* free if this is reconfig */
			free(option->opt_str);
		option->opt_str = strdup(s);
		break;
	default:
		LOG("general", GB_LOG_ERROR,
		    "option type %d not supported!\n", option->type);
		break;
	}
}

static void glusterBlockParseOptions(struct gb_config *cfg, char *buf, int len, bool reloading)
{
	char *cur = buf, *end = buf + len;

	while (cur < end) {
		/* skip blanks lines */
		GB_SKIP_BLANK_LINES(cur, end);

		/* skip comments with '#' */
		GB_SKIP_COMMENT_LINES(cur, end);

		if (cur >= end)
			break;

		if (!isalpha(*cur))
			continue;

		/* parse the options from config file to gb_options[] */
		glusterBlockParseOption(&cur, end);
	}

	/* parse the options from gb_options[] to struct gb_config */
	glusterBlockConfSetOptions(cfg, reloading);
}

static int glusterBlockLoadConfig(struct gb_config *cfg, bool reloading)
{
	int ret = -1;
	int fd, len;
	char *buf;

	buf = malloc(GB_MAX_CFG_FILE_SIZE);
	if (!buf)
		return -ENOMEM;

	fd = open(cfg->path, O_RDONLY);
	if (fd < 0) {
		LOG("general", GB_LOG_ERROR,
		    "Failed to open file '%s', %m\n", cfg->path);
		goto free_buf;
	}

	len = glusterBlockReadConfig(fd, buf, GB_MAX_CFG_FILE_SIZE);
	close(fd);
	if (len < 0) {
		LOG("general", GB_LOG_ERROR,
		    "Failed to read file '%s'\n", cfg->path);
		goto free_buf;
	}

	buf[len] = '\0';

	glusterBlockParseOptions(cfg, buf, len, reloading);

	ret = 0;
free_buf:
	free(buf);
	return ret;
}

#define BUF_LEN 1024
static void *glusterBlockDynConfigStart(void *arg)
{
	struct gb_config *cfg = arg;
	int monitor, wd, len;
	char buf[BUF_LEN];

	monitor = inotify_init();
	if (monitor == -1) {
		LOG("general", GB_LOG_ERROR,
		    "Failed to init inotify %d\n", monitor);
		return NULL;
	}

	wd = inotify_add_watch(monitor, cfg->path, IN_ALL_EVENTS);
	if (wd == -1) {
		LOG("general", GB_LOG_ERROR,
		    "Failed to add \"%s\" to inotify %m\n", cfg->path);
		return NULL;
	}

	LOG("general", GB_LOG_INFO,
	    "Inotify is watching \"%s\", wd: %d, mask: IN_ALL_EVENTS\n",
		  cfg->path, wd);

	while (1) {
		struct inotify_event *event;
		char *p;

		len = read(monitor, buf, BUF_LEN);
		if (len == -1) {
			LOG("general", GB_LOG_WARNING, "Failed to read inotify: %d\n", len);
			continue;
		}

		for (p = buf; p < buf + len;) {
			event = (struct inotify_event *)p;

			LOG("general", GB_LOG_INFO, "event->mask: 0x%x\n", event->mask);

			if (event->wd != wd)
				continue;

			/*
			 * If force to write to the unwritable or crashed
			 * config file, the vi/vim will try to move and
			 * delete the config file and then recreate it again
			 * via the *.swp
			 */
			if ((event->mask & IN_IGNORED) && !access(cfg->path, F_OK))
				wd = inotify_add_watch(monitor, cfg->path, IN_ALL_EVENTS);

			/* Try to reload the config file */
			if (event->mask & IN_MODIFY || event->mask & IN_IGNORED)
				glusterBlockLoadConfig(cfg, true);

			p += sizeof(struct inotify_event) + event->len;
		}
	}

	return NULL;
}

struct gb_config *glusterBlockSetupConfig(const char *path)
{
	struct gb_config *cfg;
	int ret;

	if (!path)
		path = "/etc/sysconfig/gluster-blockd"; /* the default config file */

	cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		LOG("general", GB_LOG_ERROR, "Alloc GB config failed for path: %s!\n", path);
		return NULL;
	}

	cfg->path = strdup(path);
	if (!cfg->path) {
		LOG("general", GB_LOG_ERROR, "failed to copy path: %s\n", path);
		goto free_cfg;
	}

	if (glusterBlockLoadConfig(cfg, false)) {
		LOG("general", GB_LOG_ERROR, "Loading GB config failed for path: %s!\n", path);
		goto free_path;
	}

	/*
	 * If the dynamic reloading thread fails to start, it will fall
	 * back to static config
	 */
	ret = pthread_create(&cfg->thread_id, NULL, glusterBlockDynConfigStart, cfg);
	if (ret) {
		LOG("general", GB_LOG_WARNING,
		    "Dynamic config started failed, fallling back to static %d!\n", ret);
	} else {
		cfg->is_dynamic = true;
	}

	return cfg;

free_path:
	free(cfg->path);
free_cfg:
	free(cfg);
	return NULL;
}

static void glusterBlockCancelConfigThread(struct gb_config *cfg)
{
	pthread_t thread_id = cfg->thread_id;
	void *join_retval;
	int ret;

	ret = pthread_cancel(thread_id);
	if (ret) {
		LOG("general", GB_LOG_ERROR,
		    "pthread_cancel failed with value %d\n", ret);
		return;
	}

	ret = pthread_join(thread_id, &join_retval);
	if (ret) {
		LOG("general", GB_LOG_ERROR,
		    "pthread_join failed with value %d\n", ret);
		return;
	}

	if (join_retval != PTHREAD_CANCELED)
		LOG("general", GB_LOG_ERROR,
		    "unexpected join retval: %p\n", join_retval);
}

void glusterBlockDestroyConfig(struct gb_config *cfg)
{
	struct list_head *pos, *q;
	struct gb_conf_option *option;

	if (!cfg)
		return;

	if (cfg->is_dynamic)
		glusterBlockCancelConfigThread(cfg);

	list_for_each_safe(pos, q, &gb_options) {
		option = list_entry(pos, struct gb_conf_option, list);
		list_del(&option->list);

		if (option->type == GB_OPT_STR)
			free(option->opt_str);
		free(option->key);
		free(option);
	}

	glusterBlockConfFreeStrKeys(cfg);
	free(cfg->path);
	free(cfg);
}
