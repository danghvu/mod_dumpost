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

#include "mod_dumpost.h"

module AP_MODULE_DECLARE_DATA dumpost_module;

static void dumpit(ap_filter_t *f, apr_bucket *b, char *buf, apr_size_t *current_size) {

    dumpost_cfg_t *cfg =
        (dumpost_cfg_t *) ap_get_module_config(f->r->per_dir_config, &dumpost_module);

    if (!(APR_BUCKET_IS_METADATA(b))) {
        const char * ibuf;
        apr_size_t nbytes;
        if (apr_bucket_read(b, &ibuf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                nbytes = min(nbytes, cfg->max_size - *current_size);
                strncpy(buf, ibuf, nbytes);
                *current_size += nbytes;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                    "mod_dumpost: error reading data");
        }
    }
}

apr_status_t dumpost_input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {

    apr_bucket *b;
    apr_status_t ret;
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
        state->header_printed = 0;
    } 

    dumpost_cfg_t *cfg =
        (dumpost_cfg_t *) ap_get_module_config(f->r->per_dir_config, &dumpost_module);

    if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS)
        return ret;

    char *buf = apr_palloc(state->mp, cfg->max_size);
    apr_size_t buf_len = 0;
    char **headers = (cfg->headers->nelts > 0)?(char **) cfg->headers->elts : NULL;

    /* dump header if config */    
    if (state->log_size != LOG_IS_FULL && headers!=NULL && !state->header_printed) {
        int i=0; 
        for (;i<cfg->headers->nelts;i++) {
            const char *s = apr_table_get(f->r->headers_in, headers[i]);
            if (s == NULL) continue;
            int len = strlen(s);
            len = min(len, cfg->max_size - len);
            strncpy(buf + buf_len, s, len);
            buf_len += len + 1;
            buf[buf_len-1] = ' ';
            if (buf_len == cfg->max_size) break;            
        }
        state->header_printed = 1;
    }

    /* dump body */
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) 
        if (state->log_size != LOG_IS_FULL && buf_len < cfg->max_size) 
            dumpit(f, b, buf + buf_len, &buf_len);

    if (buf_len && state->log_size != LOG_IS_FULL) {
        buf_len = min(buf_len, cfg->max_size - state->log_size);
        buf[buf_len] = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                "\"%s\" %s", f->r->the_request, buf);
        state->log_size += buf_len;

        if (state->log_size == cfg->max_size){
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r, "mod_dumpost: body limit reach");
            state->log_size = LOG_IS_FULL;
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

static const command_rec dumpost_cmds[] = {
    AP_INIT_TAKE1("DumpPostMaxSize", dumpost_set_max_size, NULL,  RSRC_CONF, "Set maximum data size"),
    AP_INIT_ITERATE("DumpPostHeaderAdd", dumpost_add_header, NULL, RSRC_CONF, "Add header to log"),
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
