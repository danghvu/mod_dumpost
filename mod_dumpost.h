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

#ifndef __MOD_DUMPOST__
#define __MOD_DUMPOST__

#define LOG_IS_FULL -1
#define DEFAULT_MAX_SIZE 1024*1024
#define min(a,b) (a)<(b)?(a):(b)
#define CREATEMODE ( APR_UREAD | APR_UWRITE | APR_GREAD )

typedef struct dumpost_cfg_t {
    apr_pool_t *pool;
    apr_size_t max_size;
    apr_array_header_t *headers;
    char *file;
} dumpost_cfg_t;

typedef struct {
    apr_pool_t *mp;
    int log_size;
    int header_printed;
    char *buffer;
    apr_file_t *fd;
} request_state;

#endif
