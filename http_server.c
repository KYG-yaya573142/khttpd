#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/types.h>

#include "fibdrv.h"
#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_200                                      \
    ""                                                         \
    "HTTP/1.1 %s" CRLF "Server: " KBUILD_MODNAME CRLF          \
    "Content-Type: text/plain" CRLF "Content-Length: %lu" CRLF \
    "Connection: %s" CRLF CRLF "%s" CRLF

#define RECV_BUFFER_SIZE 4096
#define MSG_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static char *do_fibonacci(char *num_ptr)
{
    int n = -1;
    char *msg = kmalloc(MSG_BUFFER_SIZE, GFP_KERNEL);
    char *next_tok;
    int num_length = 0;
    num_ptr += 5;  // skip "/fib/"
    next_tok = strstr(num_ptr, "/");
    if (!next_tok)
        num_length = strlen(num_ptr);
    else
        num_length = (uint64_t) next_tok - (uint64_t) num_ptr;
    strncpy(msg, num_ptr, num_length);  // no modification on original URL
    msg[num_length] = '\0';
    kstrtoint(msg, 10, &n);

    if (n < 0) {
        snprintf(msg, MSG_BUFFER_SIZE, "fib(%d): invalid arguments!", n);
    } else {
        long long result = fib_sequence_fdouble(n);
        snprintf(msg, MSG_BUFFER_SIZE, "fib(%d): %lld", n, result);
    }
    return msg;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    char *connection = keep_alive ? "Keep-Alive" : "Close";
    char *status = "501 Not Implemented";
    char *body = "501 Not Implemented";
    char *response = NULL;
    char *target = NULL;
    bool flag = 0;

    pr_info("requested_url = %s\n", request->request_url);
    if (request->method == HTTP_GET) {
        status = "200 OK";
        body = "Hello World!";
    }

    /* fib function entry */
    if ((target = strstr(request->request_url, "/fib/"))) {
        flag = 1;
        body = do_fibonacci(target);
    }

    response = kmalloc(MSG_BUFFER_SIZE, GFP_KERNEL);
    snprintf(response, MSG_BUFFER_SIZE, HTTP_RESPONSE_200, status, strlen(body),
             connection, body);
    http_server_send(request->socket, response, strlen(response));
    kfree(response);
    if (flag)
        kfree(body);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    if (len > 127) {  // max length = 128 - 1 ('\0')
        pr_err("url error: url too long!\n");
        len = 127;
    }
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static int http_server_worker(void *arg)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return 0;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        worker = kthread_run(http_server_worker, socket, KBUILD_MODNAME);
        if (IS_ERR(worker)) {
            pr_err("can't create more worker process\n");
            continue;
        }
    }
    return 0;
}
