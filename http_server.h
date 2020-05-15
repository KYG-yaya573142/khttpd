#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_server {
    bool is_stopped;
    struct list_head worker_head;
};

struct khttpd {
    struct socket *socket;
    struct list_head list;
    struct work_struct worker;
};

extern int http_server_daemon(void *arg);

#endif
