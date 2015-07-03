
#ifndef _HAVE_STATS_H
#define _HAVE_STATS_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

struct uri_record {
    char *uri;
    int dst_port;
    struct  in_addr dst_addr;
    int src_port;
    struct in_addr src_addr;
    unsigned int ack;
    unsigned int seq;
    unsigned int tcp_datalen;
    long in_datalen;
    long out_datalen;
};

void init_stats(int display_interval, int printable);
void cleanup_stats();
void display_stats(int printable);
int update_stats(struct uri_record *record, struct timeval t);
int finish_request(struct uri_record *record, struct timeval t, int is_fin);
void fin_response(struct uri_record *record);
void update_request_continued(struct uri_record *record, struct timeval tv);
void update_request_datalen(struct uri_record *record);
#endif /* ! _HAVE_RATE_H */
