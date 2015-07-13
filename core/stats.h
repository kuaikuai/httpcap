#ifndef _HAVE_STATS_H
#define _HAVE_STATS_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#define URI_LEN 32
#define METHOD_LEN 8
struct uri_record {
    char uri[URI_LEN];
    char method[METHOD_LEN];
    int dst_port;
    struct  in_addr dst_addr;
    int src_port;
    struct in_addr src_addr;
    unsigned int ack;
    unsigned int seq;
    unsigned int tcp_datalen;
    int status_code;
    struct timeval timestamp;
    int direction;
    struct uri_record *next;
};

void init_stats(int display_interval, int printable);
void cleanup_stats();
void display_stats(int printable);
void update_stats(struct uri_record *record, struct timeval t);
void finish_request(struct uri_record *record, struct timeval t);
void update_request_continued(struct uri_record *record, struct timeval tv);
#endif /* ! _HAVE_RATE_H */
