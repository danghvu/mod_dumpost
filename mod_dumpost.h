#ifndef __MOD_DUMPOST__
#define __MOD_DUMPOST__

#define DEFAULT_MAX_SIZE 1024*1024
#define min(a,b) (a)<(b)?(a):(b)

typedef struct dumpost_conf_t {
    apr_size_t max_size;
} dumpost_conf_t;

#endif
