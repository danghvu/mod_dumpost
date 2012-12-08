/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#include "mod_dumpost.h"

module AP_MODULE_DECLARE_DATA dumpost_module;

static void dumpit(ap_filter_t *f, apr_bucket *b, char *buf, apr_size_t *current_size)
{
    dumpost_conf_t *conf_ptr =
    (dumpost_conf_t *) ap_get_module_config(f->c->base_server->module_config, &dumpost_module);
       

    if (!(APR_BUCKET_IS_METADATA(b))) {
        const char * ibuf;
        apr_size_t nbytes;
        if (apr_bucket_read(b, &ibuf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                nbytes = min(nbytes, conf_ptr->max_size - *current_size);
                memcpy(buf, ibuf, nbytes);
                *current_size += nbytes;
            }
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
                 "mod_dumpost: error reading data");
        }
    }
}

apr_status_t dumpost_input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *b;
    apr_status_t ret;
    /* restoring state */
    request_state *state = f->ctx;
    if (state == NULL) {
        /* create state if not yet */
        apr_pool_t *mp;
        if (ret = apr_pool_create(&mp, NULL) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server, "mod_dumpost: unable to create memory pool");
            return ret;
        }
        f->ctx = state = (request_state *) apr_palloc(mp, sizeof *state);
        state->mp = mp;
        state->reach_body = 0;
        state->body_size = 0;
    } 

    dumpost_conf_t *conf =
        (dumpost_conf_t *) ap_get_module_config(f->c->base_server->module_config, &dumpost_module);

    if (ret = ap_get_brigade(f->next, bb, mode, block, readbytes) != APR_SUCCESS)
        return ret;

    char *buf = apr_palloc(state->mp, conf->max_size);
    apr_size_t buf_len = 0;
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) 
        if (state->body_size != -1)
            dumpit(f, b, buf + buf_len, &buf_len);

    if (state->body_size == -1) return APR_SUCCESS;

    if (buf_len) {
        buf[buf_len] = '\0';
        if (state->reach_body) {
            buf_len = min(buf_len, conf->max_size - state->body_size);
            buf[buf_len] = '\0';
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server,
                    "[client: %s] %s", f->c->remote_ip, buf);
            state->body_size += buf_len;

            if (state->body_size == conf->max_size){
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, f->c->base_server, "mod_dumpost: [client %s] body limit reach", f->c->remote_ip);
                state->body_size = -1;
            }
        }
        if ( strcmp(buf,"\r\n") == 0 )
            state->reach_body = 1;
    } 

    return APR_SUCCESS;
}

static int dumpost_pre_conn(conn_rec *c, void *csd)
{
    ap_add_input_filter("DUMPOST_IN", NULL, NULL, c);

    return OK;
}

static void dumpost_register_hooks(apr_pool_t *p)
{
  ap_register_input_filter("DUMPOST_IN", dumpost_input_filter,
	NULL, AP_FTYPE_CONNECTION + 3) ;
  ap_hook_pre_connection(dumpost_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *dumpost_create_sconfig(apr_pool_t *mp, server_rec *s) {
    dumpost_conf_t *conf_ptr = apr_pcalloc(mp, sizeof(dumpost_conf_t));
    conf_ptr->max_size = DEFAULT_MAX_SIZE;
    return conf_ptr;
}

static const char *dumpost_set_max_size(cmd_parms *cmd, void *dummy, const char *arg) {
    dumpost_conf_t *conf_ptr = ap_get_module_config(cmd->server->module_config, &dumpost_module);
    conf_ptr->max_size = atoi(arg);
    if (conf_ptr->max_size == 0) 
        conf_ptr->max_size = DEFAULT_MAX_SIZE;
    return NULL;
}

static const command_rec dumpost_cmds[] = {
    AP_INIT_TAKE1("DumpPostMaxSize", dumpost_set_max_size, NULL,  RSRC_CONF, "Set maximum data size"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA dumpost_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	dumpost_create_sconfig,
	NULL,
	dumpost_cmds,
	dumpost_register_hooks
};
