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

static void dumpit(ap_filter_t *f, apr_bucket *b, apr_pool_t *mp, char *buf, apr_size_t *current_size)
{
    conn_rec *c = f->c;
   
    dumpost_conf_t *conf_ptr =
    (dumpost_conf_t *) ap_get_module_config(c->base_server->module_config, &dumpost_module);
       

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
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
                 "dumpost:  %s (%s-%s) [%s]: %s",
                 f->frec->name,
                 (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data",
                 b->type->name,
                 c->remote_ip,
                 "error reading data");
        }
    }
}

int print = 0;

apr_status_t dumpost_input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *b;
    apr_status_t ret;
    conn_rec *c = f->c;
    dumpost_conf_t *conf_ptr =
        (dumpost_conf_t *) ap_get_module_config(c->base_server->module_config, &dumpost_module);

    ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (ret == APR_SUCCESS) {
        apr_pool_t *mp;
        apr_status_t ret1;
        if ( (ret1 = apr_pool_create(&mp, NULL)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "mod_dumpost: can't allocate memory");
            return ret1;
        }

        char *buf;
        buf = apr_palloc(mp, conf_ptr->max_size);
        apr_size_t buf_len = 0;
        for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) 
            dumpit(f, b, mp, buf + buf_len, &buf_len);
        if (buf_len) {
            buf[buf_len] = '\0';
            if (print)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                        "[client: %s] %s",
                        c->remote_ip, buf);
            if ( strstr(buf,"\r\n") == buf ) 
                print=1;
        } else print = 0;
        
        apr_pool_destroy(mp);
    }

    return ret;
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

static const char *dumpost_set_max_size(cmd_parms *cmd, void *dummy, int arg) {
    dumpost_conf_t *conf_ptr = ap_get_module_config(cmd->server->module_config, &dumpost_module);
    conf_ptr->max_size = arg;
    return NULL;
}

static const command_rec dumpost_cmds[] = {
    AP_INIT_FLAG("DumpPostMaxSize", dumpost_set_max_size, NULL,  RSRC_CONF, "Set maximum data size"),
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
