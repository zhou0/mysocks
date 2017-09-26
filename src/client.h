/* 
 *  * File:   client.h
 *   * Author: lzhou
 *    *
 *     * Created on 2017年4月16日, 下午 5:40
 *      */

#ifndef CLIENT_H
#define	CLIENT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "defs.h"
  
 void do_next(client_ctx *cx);
 int do_handshake(client_ctx *cx);
 int do_handshake_auth(client_ctx *cx);
 int do_req_start(client_ctx *cx);
 int do_req_parse(client_ctx *cx);
 int do_req_lookup(client_ctx *cx);
 int do_req_connect_start(client_ctx *cx);
 int do_req_connect(client_ctx *cx);
 int do_proxy_start(client_ctx *cx);
 int do_proxy(client_ctx *cx);
 int do_kill(client_ctx *cx);
 int do_almost_dead(client_ctx *cx);
 int conn_cycle(const char *who, conn *a, conn *b);
 void conn_timer_reset(conn *c);
// void conn_timer_expire(uv_timer_t *handle, int status);
 void conn_timer_expire(uv_timer_t *handle);
 void conn_getaddrinfo(conn *c, const char *hostname);
 void conn_getaddrinfo_done(uv_getaddrinfo_t *req,
                                  int status,
                                  struct addrinfo *ai);
 int conn_connect(conn *c);
 void conn_connect_done(uv_connect_t *req, int status);
 void conn_read(conn *c);
 void conn_read_done(uv_stream_t *handle,
                           ssize_t nread,
                           const uv_buf_t *buf);
 void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
 void conn_write(conn *c, const void *data, unsigned int len);
 void conn_write_done(uv_write_t *req, int status);
 void conn_close(conn *c);
 void conn_close_done(uv_handle_t *handle);

#ifdef	__cplusplus
}
#endif

#endif	/* CLIENT_H */


