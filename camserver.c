/*
 * h264 rtsp to tcp/http server
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <signal.h>

/* For inet_ntoa. */
#include <arpa/inet.h>

/* Required by event.h. */
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>

/* Libevent. */
#include <event.h>

#define TCP_SERVER_PORT 4264
#define HTTP_SERVER_PORT 8264

#define HTTP_READ_TIMEOUT 30
#define FFMPEG_READ_TIMEOUT 30

#define HTTP_READ_BUFFER 16384
#define HTTP_MAX_REQUEST_SIZE 65536


static char buffer[1048576];
static size_t buffer_size = 0;

static char tsbuffer[65536];

static char *ffh264[] = {
    "ffmpeg", "-nostdin", "-nostats", "-hide_banner", "-v", "repeat+info", "-fflags", "nobuffer",
    //"-i", "rtsp://172.16.0.101:554/user=admin&password=tlJwpbo6&channel=0&stream=0.sdp?real_stream",
    "-i", "/dev/null",
    "-vcodec", "copy", "-an", "-sn", "-f", "h264", "-",
    NULL
};

static char *ffts[] = {
    "ffmpeg", "-nostdin", "-nostats", "-hide_banner", "-v", "repeat+info", "-fflags", "nobuffer",
    "-analyzeduration", "40000", "-use_wallclock_as_timestamps", "1", "-i", "-",
    "-vcodec", "copy", "-an", "-sn", "-f", "mpegts", "-",
    NULL
};

static char http_reply[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-type: video/mp2t\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n";

struct child {
    pid_t pid;
    int stdin;
    int stdout;
    struct event ev;
};

static struct child *ffmpeg;

struct h264_client {
    struct h264_client *next;
    struct event ev;
    int event_del;
    int waitkey;
    int fd;
};

struct http_client {
    struct http_client *next;
    struct h264_client *h264;
    struct child *ffmpeg;
    struct event ev;
    size_t reqsize;
    char *request;
    int waitreq;
    int fd;
};

static struct h264_client *h264_clients = NULL;
static struct http_client *http_clients = NULL;

struct cache_unit {
    struct cache_unit *next;
    struct cache_unit *prev;
    size_t            size;
    unsigned char     type;
    char              data[0];
};

#define CACHE_MAX 32
static unsigned cache_size = 0;
static struct cache_unit *cache_head = NULL;
static struct cache_unit *cache_tail = NULL;


int setfdflags(int fd, int flags)
{
    int fl;

    fl = fcntl(fd, F_GETFL);
    if (fl < 0)
        return flags;

    fl |= O_NONBLOCK | O_CLOEXEC;
    if (fcntl(fd, F_SETFL, fl) < 0)
        return -1;

    return 0;
}


int setmaxpipesize(int fd)
{
    int s1, s2;

    s1 = fcntl(fd, F_GETPIPE_SZ);

    if (s1 < 1048576) {
        for (s2 = 1048576; s2 > s1; s2 /= 2)
            if (fcntl(fd, F_SETPIPE_SZ, s2) == s2)
                return 0;
    } else
        return 0;

    fprintf(stderr, "pipe size is only %d bytes\n", s1);
    return -1;
}


struct child *ffmpeg_spawn(char *const argv[])
{
    struct child *chld;
    int fdin[2], fdout[2];

    chld = malloc(sizeof(struct child));
    if (chld == NULL) {
        fprintf(stderr, "not enough memory\n");
        return NULL;
    }

    if (pipe(fdin) == -1) {
        warn("pipe failed");
        free(chld);
        return NULL;
    }

    if (pipe(fdout) == -1) {
        warn("pipe failed");
        close(fdin[0]);
        close(fdin[1]);
        free(chld);
        return NULL;
    }

    chld->pid = fork();

    if (chld->pid == -1) {
        warn("fork failed");
        close(fdin[0]);
        close(fdin[1]);
        close(fdout[0]);
        close(fdout[1]);
        free(chld);
        return NULL;
    }

    if (chld->pid == 0) {
        if (dup2(fdin[0], STDIN_FILENO) == -1)
            err(1, "dup stdout failed");

        if (dup2(fdout[1], STDOUT_FILENO) == -1)
            err(1, "dup stdout failed");

        close(fdin[0]);
        close(fdin[1]);
        close(fdout[0]);
        close(fdout[1]);

        prctl(PR_SET_PDEATHSIG, SIGTERM);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        execvp(argv[0], argv);
        err(1, "exec %s failed", argv[0]);
    }

    close(fdin[0]);
    close(fdout[1]);
    chld->stdin = fdin[1];
    chld->stdout = fdout[0];

    if (setfdflags(chld->stdin, O_CLOEXEC | O_NONBLOCK))
        warn("setfdflags failed");

    if (setfdflags(chld->stdout, O_CLOEXEC | O_NONBLOCK))
        warn("setfdflags failed");

    if (setmaxpipesize(chld->stdin))
        warn("setmaxpipesize failed");

    return chld;
}


void process_unit(struct cache_unit *unit)
{
    struct h264_client *curr, *prev, *temp;

    for (curr = h264_clients; curr; curr = curr->next) {
        // IDR frame
        if (curr->waitkey && unit->type == 5) {
            struct cache_unit *u;

            // playback SEI, SPS and PPS frames
            for (u = unit; u->prev; u = u->prev) {
                struct cache_unit *p = u->prev;

                if (p->type != 6 && p->type != 7 && p->type != 8)
                    break;
            }

            // send SEI, SPS and PPS frames to client
            for (; u != unit; u = u->next) {
                ssize_t w = write(curr->fd, u->data, u->size);

                if (w == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        fprintf(stderr, "h264 client too slow");
                    } else {
                        warn("h264 write failed");
                        if (curr->event_del)
                            event_del(&curr->ev);
                        close(curr->fd);
                        curr->fd = -1;
                    }
                } else
                if (w < u->size)
                    fprintf(stderr, "h264 pipe underwrite\n");
            }

            curr->waitkey = 0;
        }

        if (!curr->waitkey && curr->fd >= 0) {
            ssize_t w = write(curr->fd, unit->data, unit->size);

            if (w == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    fprintf(stderr, "h264 client too slow\n");
                } else {
                    warn("h264 write failed");
                    if (curr->event_del)
                        event_del(&curr->ev);
                    close(curr->fd);
                    curr->fd = -1;
                }
            } else
            if (w < unit->size)
                fprintf(stderr, "h264 pipe underwrite (X)\n");
        }
    }

    prev = NULL;
    curr = h264_clients;

    while (curr) {
        if (curr->fd != -1) {
            prev = curr;
            curr = curr->next;
            continue;
        }

        if (prev == NULL)
            h264_clients = curr->next;
        else
            prev->next = curr->next;

        temp = curr;
        curr = curr->next;
        free(temp);
    }
}


void on_h264_read(int fd, short ev, void *arg)
{
    struct cache_unit *unit;
    size_t want, size;
    ssize_t got;
    int i, s;

    if (ev == EV_TIMEOUT) {
        kill(ffmpeg->pid, SIGTERM);
        fprintf(stderr, "read timeout");
        exit(1);
    }

    want = sizeof(buffer) - buffer_size;
    if (want > 65536)
        want = 65536;

    if (want == 0) {
        fprintf(stderr, "stream buffer overflow\n");
        exit(1);
    }

    got = read(fd, buffer + buffer_size, want);
    if (got == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        err(1, "read failed");
    }

    if (got == 0) {
        fprintf(stderr, "ffmpeg exited\n");
        exit(0);
    }

    /* parse NAL units */
    buffer_size += got;

    if (buffer_size < 9)
        return;

    if (buffer[0] != 0 || buffer[1] != 0 ||
        buffer[2] != 0 || buffer[3] != 1) {
        fprintf(stderr, "malformed stream: bad NAL unit boundary\n");
        exit(1);
    }

    for (i = 8, s = 0; i < buffer_size; i++) {
        if (buffer[i] != 1 || buffer[i - 1] || buffer[i - 2] || buffer[i - 3])
            continue;

        size = i - s - 3;

        unit = malloc(sizeof(struct cache_unit) + size);
        if (unit == NULL) {
            fprintf(stderr, "malloc failed\n");
            exit(1);
        }

        if (cache_head) {
            cache_head->next = unit;
            unit->prev = cache_head;
            unit->next = NULL;
            cache_head = unit;
        } else {
            unit->next = NULL;
            unit->prev = NULL;
            cache_head = unit;
            cache_tail = unit;
        }

        memcpy(unit->data, buffer + s, size);
        unit->type = unit->data[4] & 0x1f;
        unit->size = size;
        cache_size++;

        process_unit(unit);

        s += size;
    }

    if (s > 0) {
        buffer_size -= s;
        memmove(buffer, buffer + s, buffer_size);

        /* cache cleanup */
        while (cache_size > CACHE_MAX) {
            if (cache_tail->next) {
                unit = cache_tail;
                cache_tail = unit->next;
                cache_size--;
                free(unit);
            } else
                break;
        }
    }

    return;
}


void on_tcp_read(int fd, short ev, void *arg)
{
    struct h264_client *client = (struct h264_client *)arg;
    struct h264_client *curr;

    if (client == h264_clients)
        h264_clients = client->next;
    else {
        for (curr = h264_clients; curr->next != client; curr = curr->next);
        curr->next = client->next;
    }

    free(client);
    close(fd);
}


void on_tcp_accept(int fd, short ev, void *arg)
{
    int client_fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    struct h264_client *client;

    /* Accept the new connection. */
    client_fd = accept4(fd, (struct sockaddr *)&addr, &len,
                        SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("tcp accept failed");
        return;
    }

    client = malloc(sizeof(struct h264_client));
    if (client == NULL) {
        fprintf(stderr, "malloc failed\n");
        close(client_fd);
        return;
    }

    event_set(&client->ev, client_fd, EV_READ, on_tcp_read, client);
    event_add(&client->ev, NULL);

    client->event_del = 1;
    client->fd = client_fd;
    client->waitkey = 1;

    client->next = h264_clients;
    h264_clients = client;
}


void http_client_close(struct http_client *client)
{
    if (client == http_clients)
        http_clients = client->next;
    else {
        struct http_client *curr;
        for (curr = http_clients; curr->next != client; curr = curr->next);
        curr->next = client->next;
    }

    event_del(&client->ev);

    if (client->h264) {
        if (client->h264 == h264_clients)
            h264_clients = client->h264->next;
        else {
            struct h264_client *curr;
            for (curr = h264_clients; curr->next != client->h264; curr = curr->next);
            curr->next = client->h264->next;
        }

        if (!client->ffmpeg || client->ffmpeg->stdin != client->h264->fd)
            close(client->h264->fd);

        if (client->h264->event_del)
            event_del(&client->h264->ev);

        free(client->h264);
    }

    if (client->ffmpeg) {
        kill(client->ffmpeg->pid, SIGTERM);
        event_del(&client->ffmpeg->ev);
        close(client->ffmpeg->stdout);
        close(client->ffmpeg->stdin);
        free(client->ffmpeg);
    }

    if (client->request)
        free(client->request);

    close(client->fd);

    free(client);
}


void on_ffts_read(int fd, short ev, void *arg)
{
    struct http_client *client = (struct http_client *)arg;
    struct iovec iov[2];
    char header[16];
    ssize_t ret;

    if (ev == EV_TIMEOUT) {
        fprintf(stderr, "ffts read timeout\n");
        goto close;
    }

    ret = read(fd, tsbuffer, sizeof(tsbuffer));

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        goto close;
    }

    if (ret == 0)
        goto close;

    iov[0].iov_base = header;
    iov[0].iov_len = snprintf(header, sizeof(header), "\r\n%X\r\n", (unsigned int)ret);
    iov[1].iov_base = tsbuffer;
    iov[1].iov_len = ret;

    ret = writev(client->fd, iov, 2);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        goto close;
    }

    return;

  close:
    http_client_close(client);
}


void on_http_read(int fd, short ev, void *arg)
{
    struct http_client *client = (struct http_client *)arg;
    struct timeval tv;
    char *buffer;
    ssize_t ret;
    int start;
    void *b;

    if (ev == EV_TIMEOUT) {
        fprintf(stderr, "http client read timeout\n");
        goto close;
    }

    if (!client->waitreq)
        goto close;

    buffer = realloc(client->request, client->reqsize + HTTP_READ_BUFFER);
    if (buffer == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto close;
    }
    client->request = buffer;

    ret = read(fd, buffer + client->reqsize, HTTP_READ_BUFFER);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else {
            fprintf(stderr, "read failed\n");
            goto close;
        }
    }

    if (ret == 0)
        goto close;

    start = client->reqsize - 3;
    client->reqsize += ret;

    if (start < 0) {
        if (client->reqsize > 4)
            b = memmem(client->request, client->reqsize, "\r\n\r\n", 4);
        else
            b = NULL;
    } else
        b = memmem(client->request + start, client->reqsize - start,
                   "\r\n\r\n", 4);

    if (b == NULL)
        return;

    client->waitreq = 0;
    free(client->request);
    client->request = NULL;

    if (write(fd, http_reply, strlen(http_reply)) == -1)
        goto close;

    client->ffmpeg = ffmpeg_spawn(ffts);
    if (client->ffmpeg == NULL)
        goto close;

    client->h264 = malloc(sizeof(struct h264_client));
    if (client->h264 == NULL)
        goto close;

    client->h264->waitkey = 1;
    client->h264->event_del = 0;
    client->h264->fd = client->ffmpeg->stdin;

    client->h264->next = h264_clients;
    h264_clients = client->h264;

    event_set(&client->ffmpeg->ev, client->ffmpeg->stdout,
              EV_READ | EV_TIMEOUT | EV_PERSIST, on_ffts_read, client);

    tv.tv_sec = FFMPEG_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&client->ffmpeg->ev, &tv);

    event_del(&client->ev);
    event_add(&client->ev, NULL);

    return;

  close:
    http_client_close(client);
}


void on_http_accept(int fd, short ev, void *arg)
{
    int client_fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    struct http_client *client;
    struct timeval tv;

    /* Accept the new connection. */
    client_fd = accept4(fd, (struct sockaddr *)&addr, &len,
                        SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("http accept failed");
        return;
    }

    client = malloc(sizeof(struct http_client));
    if (client == NULL) {
        fprintf(stderr, "malloc failed\n");
        close(client_fd);
        return;
    }

    event_set(&client->ev, client_fd, EV_READ | EV_TIMEOUT | EV_PERSIST,
               on_http_read, client);

    tv.tv_sec = HTTP_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&client->ev, &tv);

    client->fd = client_fd;
    client->h264 = NULL;
    client->ffmpeg = NULL;
    client->reqsize = 0;
    client->request = NULL;
    client->waitreq = 1;

    client->next = http_clients;
    http_clients = client;
}


int main(int argc, char **argv)
{
    int tcp_listen_fd;
    int http_listen_fd;
    struct sockaddr_in addr;
    int reuseaddr_on = 1;
    struct timeval tv;

    /* tcp/http socket accept events */
    struct event ev_tcp_accept;
    struct event ev_http_accept;

    /* check args */
    if (argc < 2) {
        fprintf(stderr, "Usage: camserver <rtsp-uri>\n");
        return 1;
    }

    ffh264[9] = argv[1];

    /* Initialize libevent */
    event_init();

    /* Setup signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /*
     * Initialize tcp listen socket
     */
    tcp_listen_fd = socket(AF_INET,
                           SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (tcp_listen_fd < 0)
        err(1, "listen failed");

    if (setsockopt(tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
        sizeof(reuseaddr_on)) == -1)
        err(1, "setsockopt failed");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // or INADDR_ANY
    //addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(TCP_SERVER_PORT);
    if (bind(tcp_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err(1, "tcp bind failed");

    if (listen(tcp_listen_fd, 5) < 0)
        err(1, "tcp listen failed");

    event_set(&ev_tcp_accept, tcp_listen_fd,
              EV_READ | EV_PERSIST, on_tcp_accept, NULL);
    event_add(&ev_tcp_accept, NULL);

    /*
     * Initialize http listen socket
     */
    http_listen_fd = socket(AF_INET,
                            SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (http_listen_fd < 0)
        err(1, "listen failed");

    if (setsockopt(http_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
        sizeof(reuseaddr_on)) == -1)
        err(1, "setsockopt failed");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // or INADDR_ANY
    //addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(HTTP_SERVER_PORT);
    if (bind(http_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err(1, "http bind failed");

    if (listen(http_listen_fd, 5) < 0)
        err(1, "http listen failed");

    event_set(&ev_http_accept, http_listen_fd,
              EV_READ | EV_PERSIST, on_http_accept, NULL);
    event_add(&ev_http_accept, NULL);

    /*
     * Start main ffmpeg
     */
    ffmpeg = ffmpeg_spawn(ffh264);
    if (ffmpeg == NULL)
        err(1, "ffmpeg start failed");

    event_set(&ffmpeg->ev, ffmpeg->stdout,
              EV_TIMEOUT | EV_READ | EV_PERSIST, on_h264_read, ffmpeg);

    tv.tv_sec = FFMPEG_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&ffmpeg->ev, &tv);

    /* Start the libevent event loop. */
    event_dispatch();

    return 0;
}
