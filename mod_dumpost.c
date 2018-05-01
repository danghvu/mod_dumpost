/*******************************************************************************
 * Copyright (c) 2012 Hoang-Vu Dang <danghvu@gmail.com>
 * This file is part of mod_dumpost
 *
 * mod_dumpost is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mod_dumpost is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mod_dumpost. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_strings.h"
#include "mod_dumpost.h"

#define DEBUG(request, format, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, format, __VA_ARGS__);

module AP_MODULE_DECLARE_DATA dumpost_module;

static void dumpit(request_rec *r, apr_bucket *b, char *buf, apr_size_t *current_size) {

    dumpost_cfg_t *cfg =
        (dumpost_cfg_t *) ap_get_module_config(r->per_dir_config, &dumpost_module);

    if (*current_size < cfg->max_size && !(APR_BUCKET_IS_METADATA(b))) {
        const char * ibuf;
        apr_size_t nbytes;
        if (apr_bucket_read(b, &ibuf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                DEBUG(r, "%ld bytes read from bucket for request %s", nbytes, r->the_request);
                nbytes = min(nbytes, cfg->max_size - *current_size);
                //strncpy(buf, ibuf, nbytes);
                for (int kk = 0; kk < nbytes; kk++) buf[kk]=ibuf[kk];
                *current_size += nbytes;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_dumpost: error reading data");
        }
    }
    else {
        if (APR_BUCKET_IS_EOS(b)) {
            DEBUG(r, "EOS bucket detected for request %s", r->the_request);
        }
    }
}

void hexArrayToStr(unsigned char* info, unsigned int infoLength, char **buffer, unsigned int start) {
    const char* pszNibbleToHex = {"0123456789ABCDEF"};
    int nNibble, i;
    for (i = 0; i < infoLength; i++) {
		nNibble = info[i] >> 4;
		buffer[0][2 * i + start] = pszNibbleToHex[nNibble];
		nNibble = info[i] & 0x0F;
		buffer[0][2 * i + 1 + start] = pszNibbleToHex[nNibble];
    }
}

apr_status_t logit(ap_filter_t *f) {
    request_state *state = f->ctx;
    request_rec *r = f->r;

    if (state == NULL || state->log_size == 0) return -1;
    state->buffer[state->log_size] = 0;

    if (state->fd == NULL) {
      // no file to write to, write to error log
      // data is truncated to MAX_STRING_LEN ~ 8192 in apache
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
              "\"%s\" %s", r->the_request, state->buffer);
    } else {
      // need to manually get the time and ip address -- too lazy to make these cusomizable
      char *time = apr_palloc(r->pool, 50);
      apr_ctime(time, r->request_time);

      // condition taken from mod_security
	  #if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
      char *ip = r->connection->client_ip;
      #else
      char *ip = r->connection->remote_ip;
	  #endif
      apr_size_t nbytes_written;
      char *text = apr_psprintf(r->pool, "[%s] %s \"%s\" ",time, ip, r->the_request);
	  
	  //Test buffer to search non ASCII characters
	  int not_bin=1;
	  for (int i = 0; i < state->log_size; i++)
	  {
		//if (state->buffer[i]==0) {
		if (state->buffer[i]<0x20 || state->buffer[i]>0x7E) {
			if (state->buffer[i]=='\n') continue;
			if (state->buffer[i]=='\r') continue;
			not_bin=0;
			break;
		}
	  }
	  
	 int jj=strlen(text);
	 dumpost_cfg_t *cfg = 
				(dumpost_cfg_t *) ap_get_module_config(f->r->per_dir_config, &dumpost_module);
	 
	 apr_status_t rc;
	 if (not_bin==0 && cfg->log_bin) {
		 char *text2 = apr_palloc(r->pool, (state->log_size*2) + 2 + jj);
		 sprintf(text2, "%s", text);
		 hexArrayToStr((unsigned char*)state->buffer, state->log_size, &text2, jj);
		 jj=jj+(state->log_size*2);
		 text2[jj]='\n';
		 jj++;
		 text2[jj]='\0';
		 rc = apr_file_write_full(state->fd, text2, jj, &nbytes_written);
	 } else {
		 if (not_bin==0) {
			 ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_dumpost: binary output is disabled, not dumping this request.");
			 return APR_SUCCESS;
		 }
		 char *text2 = apr_palloc(r->pool, (state->log_size) + 2 + jj);
		 sprintf(text2, "%s%s\n", text, state->buffer);
		 jj=strlen(text2);
		 rc = apr_file_write_full(state->fd, text2, jj, &nbytes_written);
	 }
	 if (rc != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_dumpost: error while writing to log");
		return rc;
	 }
	 apr_file_close(state->fd);
      
    }
    return APR_SUCCESS;
}

apr_status_t dumpost_input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {

    dumpost_cfg_t *cfg =
        (dumpost_cfg_t *) ap_get_module_config(f->r->per_dir_config, &dumpost_module);

    apr_bucket *b;
	apr_status_t ret;
	//Default status dont filter anything, dump all requests
	int filter_this = 0;
	char **filters = (cfg->filters->nelts > 0)?(char **) cfg->filters->elts : NULL;
	if (filters!=NULL) {
		//If theres filters present in config, discard all request until check.
		filter_this = 1;
        int fi=0;
        for (;fi<cfg->filters->nelts;fi++) {
			if (strstr(f->r->the_request, filters[fi]) != NULL) {
				//This request will be dumped.
				filter_this = 0;
				break;
			}
		}
	}
	//In case of filtering this request, exit filter.
	if (filter_this==1) {
		//Continue the filtering and exit filter before allocating memory for this request.
		if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS)
			return ret;
		return APR_SUCCESS;
	}  

	/* restoring state */
    request_state *state = f->ctx;

    if (state == NULL) {
        /* create state if not yet */
        apr_pool_t *mp;
        if ((ret = apr_pool_create(&mp, f->r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_dumpost: unable to create memory pool");
            return ret;
        }
        f->ctx = state = (request_state *) apr_palloc(mp, sizeof *state);
        state->mp = mp;
        state->log_size = 0;
        state->log_is_full = 0;
        state->header_printed = 0;
        state->buffer = apr_palloc(state->mp, cfg->max_size + 1); //1 byte more because string buffer is null terminated
        state->fd = NULL;

        if (cfg->file != 0)  {
            apr_status_t rc = apr_file_open(&state->fd, cfg->file,
                APR_FOPEN_CREATE | APR_FOPEN_APPEND | APR_FOPEN_WRITE
                , APR_OS_DEFAULT, state->mp);
            if (rc != APR_SUCCESS) {
              char buferr[50];
              apr_strerror(rc, buferr, 50);
              ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_dumpost: unable to open the log file: %s %s", cfg->file, buferr);
            }
        }
		//This doesn't work for oldest apr versions but i can obtain same result in a cleaner way using macro APR_BUCKET_IS_EOS() in dumpit function to detect when data stream ends
        apr_pool_pre_cleanup_register(state->mp, f, (apr_status_t (*)(void *))logit);
    }

    char *buf = state->buffer;
    apr_size_t buf_len = state->log_size;
    char **headers = (cfg->headers->nelts > 0)?(char **) cfg->headers->elts : NULL;

    /* dump header if config */
    if (!state->log_is_full && headers!=NULL && !state->header_printed) {
        int i=0;
        for (;i<cfg->headers->nelts;i++) {
            const char *s = apr_table_get(f->r->headers_in, headers[i]);
            if (s == NULL) continue;
            int len = strlen(s);
            len = min(len, cfg->max_size - buf_len);
            strncpy(buf + buf_len, s, len);
            buf_len += len + 1;
            buf[buf_len-1] = ' ';
            if (buf_len == cfg->max_size) break;
        }
        state->header_printed = 1;
    }

    if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS)
        return ret;

    /* dump body */
    DEBUG(f->r, "Start brigade for request: %s", f->r->the_request)
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
        if (!state->log_is_full && buf_len < cfg->max_size)
            dumpit(f->r, b, buf + buf_len, &buf_len);
    DEBUG(f->r, "End brigade for request: %s, buffer: %ld bytes", f->r->the_request, buf_len)

    if (buf_len && !state->log_is_full) {
        buf_len = min(buf_len, cfg->max_size);
        state->log_size = buf_len;

        if (state->log_size == cfg->max_size){
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r, "mod_dumpost: body limit reach");
            state->log_is_full = 1;
        }
    }

    return APR_SUCCESS;
}

static void dumpost_insert_filter( request_rec *req) {
    ap_add_input_filter("DUMPOST_IN", NULL, req, req->connection);
}

static void dumpost_register_hooks(apr_pool_t *p) {
    ap_hook_insert_filter(dumpost_insert_filter, NULL, NULL, APR_HOOK_FIRST);
    ap_register_input_filter("DUMPOST_IN", dumpost_input_filter,
            NULL, AP_FTYPE_CONTENT_SET);
}

static void *dumpost_create_dconfig(apr_pool_t *mp, char *path) {
    dumpost_cfg_t *cfg = apr_pcalloc(mp, sizeof(dumpost_cfg_t));
    cfg->max_size = DEFAULT_MAX_SIZE;
    cfg->headers = apr_array_make(mp, 0, sizeof(char *));
    cfg->pool = mp;
    cfg->file = 0;
    cfg->log_bin = 0;
	cfg->filters = apr_array_make(mp, 0, sizeof(char *));
    return cfg;
}

static const char *dumpost_set_max_size(cmd_parms *cmd, void *_cfg, const char *arg) {
    dumpost_cfg_t *cfg = (dumpost_cfg_t *) _cfg; //ap_get_module_config(cmd->server->module_config, &dumpost_module);
    cfg->max_size = atoi(arg);
    if (cfg->max_size == 0)
        cfg->max_size = DEFAULT_MAX_SIZE;
    return NULL;
}

static const char *dumpost_add_header(cmd_parms *cmd, void *_cfg, const char *arg) {
    dumpost_cfg_t *cfg = (dumpost_cfg_t *) _cfg;
    *(const char**) apr_array_push(cfg->headers) = arg;
    return NULL;
}

static const char *dumpost_log_file(cmd_parms *cmd, void *_cfg, const char *arg ){
    dumpost_cfg_t *cfg = (dumpost_cfg_t *) _cfg;
    cfg->file = (char *) arg;
    return NULL;
}

static const char *dumpost_log_binary(cmd_parms *cmd, void *_cfg, const char *arg ){
    dumpost_cfg_t *cfg = (dumpost_cfg_t *) _cfg;
	if (strstr(arg, "On") != NULL || strstr(arg, "1") != NULL)
		cfg->log_bin = 1;
	else
		cfg->log_bin = 0;
    return NULL;
}

static const char *dumpost_filter(cmd_parms *cmd, void *_cfg, const char *arg) {
    dumpost_cfg_t *cfg = (dumpost_cfg_t *) _cfg;
    *(const char**) apr_array_push(cfg->filters) = arg;
    return NULL;
}

static const command_rec dumpost_cmds[] = {
    AP_INIT_TAKE1("DumpPostMaxSize", dumpost_set_max_size, NULL,  RSRC_CONF, "Set maximum data size"),
    AP_INIT_ITERATE("DumpPostHeaderAdd", dumpost_add_header, NULL, RSRC_CONF, "Add header to log"),
    AP_INIT_TAKE1("DumpPostLogFile", dumpost_log_file, NULL, RSRC_CONF, "A custom file to log to"),
    AP_INIT_TAKE1("DumpPostLogBinary", dumpost_log_binary, NULL, RSRC_CONF, "Should log binary data (On/Off)"),
	AP_INIT_ITERATE("DumpPostFilter", dumpost_filter, NULL, RSRC_CONF, "Add matches to filter by text in the fist header"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA dumpost_module = {
    STANDARD20_MODULE_STUFF,
    dumpost_create_dconfig,
    NULL,
    NULL, //dumpost_create_sconfig,
    NULL,
    dumpost_cmds,
    dumpost_register_hooks
};
