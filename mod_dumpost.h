#ifndef __MOD_DUMPOST__
#define __MOD_DUMPOST__

#define LOG_IS_FULL -1
#define DEFAULT_MAX_SIZE 1024*1024
#define min(a,b) (a)<(b)?(a):(b)
#define DEBUG(s,t) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server, s, t);

typedef struct dumpost_cfg_t {
    apr_pool_t *pool;
    apr_size_t max_size;
    apr_array_header_t *headers; 
} dumpost_cfg_t;

typedef struct {
    apr_pool_t *mp;
    int log_size;
    int header_printed;
} request_state;

#endif
