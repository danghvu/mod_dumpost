#ifndef __MOD_DUMPOST__
#define __MOD_DUMPOST__

#define DEFAULT_MAX_SIZE 1024*1024
#define min(a,b) (a)<(b)?(a):(b)
#define DEBUG(s,t) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server, s, t);

typedef struct dumpost_conf_t {
    apr_size_t max_size;
} dumpost_conf_t;

typedef struct {
    apr_pool_t *mp;
    int reach_body;
    int body_size;
} request_state;

#endif
