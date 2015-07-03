
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>
#include "config.h"
#include "error.h"
#include "stats.h"
#include "utils.h"
#include "slab.h"

#define MAX_URI_LEN 128
#define HASH_LOG	  20
#define HASH_SIZE	  (1 << HASH_LOG)
#define HASHSIZE HASH_SIZE
#define NODE_BLOCKSIZE 100
#define MAGIC "#NUL@$#"
#define MAGIC_LEN 7
#define UDP_BUFF_COUNT 100
#define UDP_BUFF_SIZE 1024
#define SERV_PORT 50001

//#define USE_SLAB

struct udp_buffer {
    struct iovec iov[100];
    int idx;
    int used;
    int sockfd;
    int printable;
    struct sockaddr_in dest;
};
struct udp_buffer udp_buffer;
static int init = 0;
static int see_recycle = 0;
struct uri_request {
    struct uri_record record;
    struct uri_stats *stat;
    int flag;
    struct timeval timestamp;
    /* for hash table */
    struct uri_request *next;
    struct uri_request **pprev;
    /* for recycle queue */
    struct uri_request *next_req;
    struct uri_request **pprev_req;
};

struct uri_stats {
    int users;
    char uri[MAX_URI_LEN + 1];
    int port;
    struct  in_addr host;
    unsigned int count;
    long long total;
    unsigned int rps;
    time_t first_packet;
    time_t last_packet;
    float time_used;
    unsigned long timeout;
    int rep_count;
    float rep;
    long in_datalen;
    long out_datalen;
    struct uri_stats *next;
};

struct thread_args {
    unsigned int interval;
    unsigned int printable;
};
int node_count = 0;
int request_count = 0;
void create_stats_thread(int interval, int printable);
void exit_stats_thread();
void *run_stats(void *args);
struct uri_stats *get_uri(struct uri_record *record);
struct uri_stats *get_node();
void put_node(struct uri_stats *node);
struct uri_request *find_request(struct uri_record *record);
void recycle_request(time_t t);
void remove_from_recycle(struct uri_request *request);

static pthread_t thread;
static int thread_created = 0;
static pthread_mutex_t stats_lock;
static struct uri_stats **stats;
static struct uri_request **requests;
static struct uri_request requests_queue;
static struct uri_request **requests_queue_tail;
static struct thread_args thread_args;

static hurd_slab_space_t request_slab;
static hurd_slab_space_t stats_slab;


unsigned int hash_uri(struct uri_record *node)
{
    unsigned int hashval;
    int hash = 0;
    unsigned int value;
    hashval = hash_str(node->uri, HASHSIZE);
    value = node->dst_addr.s_addr;
    do {
        hash ^= value;
    } while ((value >>= HASH_LOG));

    hashval ^= hash & (HASH_SIZE - 1);
    hashval ^= node->dst_port;

    debug_ascii(node->uri,"Hash_uri");
    return hashval & (HASHSIZE - 1);
}

unsigned int hash_addr(struct  in_addr addr)
{
    int hash = 0;
    unsigned int value;
    value = addr.s_addr;
    do {
        hash ^= value;
    } while ((value >>= HASH_LOG));
    return hash;
}

unsigned int hash_request(struct uri_record *record)
{
    unsigned int hashval;

    if (record->uri) {
        hashval = hash_addr(record->src_addr);
        hashval ^= record->src_port;
    }
    else {
        hashval = hash_addr(record->dst_addr);
        hashval ^= record->dst_port;
    }
    return hashval & (HASHSIZE - 1);
}

struct uri_request *alloc_uri_request()
{
    void *p = NULL;
#ifdef USE_SLAB
    hurd_slab_alloc(request_slab, &p);
#else
    p = (void *)malloc(sizeof(struct uri_request));
#endif
    request_count++;
    return p;
}

void free_uri_request(struct uri_request *request)
{
    if(request->stat && request->stat->users > 0) request->stat->users--;
#ifdef USE_SLAB
    hurd_slab_dealloc(request_slab, request);
#else
    free(request);
#endif
    request_count--;
}

void init_stats(int interval, int printable)
{
    int err;
    if ((stats = (struct uri_stats **) calloc(HASHSIZE, sizeof(struct uri_stats *))) == NULL)
        LOG_DIE("Cannot allocate memory for host stats");

    if ((requests = (struct uri_request **) calloc(HASHSIZE, sizeof(struct uri_request *))) == NULL)
        LOG_DIE("Cannot allocate memory for requests");

    err = hurd_slab_create(sizeof(struct uri_stats), 0, NULL, NULL, NULL, NULL, NULL, &stats_slab);
    if(err) {
        LOG_DIE("Cannot allocte slab buffer\n");
    }
    err = hurd_slab_create(sizeof(struct uri_request), 0, NULL, NULL, NULL, NULL, NULL, &request_slab);
    if(err) {
        LOG_DIE("Cannot allocte slab buffer\n");
    }
    requests_queue.next_req = NULL;
    requests_queue_tail = &requests_queue.next_req;

    if(printable == 2) {
        see_recycle = 1;
    }
    create_stats_thread(interval, printable);

    return;
}

void create_stats_thread(int interval, int printable)
{
    sigset_t set;
    int s;

    if (thread_created) return;

    thread_args.interval = interval;
    thread_args.printable = printable;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);

    s = pthread_mutex_init(&stats_lock, NULL);
    if (s != 0)
        LOG_DIE("Statistics thread mutex initialization failed with error %d", s);

    s = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (s != 0)
        LOG_DIE("Statistics thread signal blocking failed with error %d", s);

    s = pthread_create(&thread, NULL, run_stats, (void *) &thread_args);
    if (s != 0)
        LOG_DIE("Statistics thread creation failed with error %d", s);

    s = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    if (s != 0)
        LOG_DIE("Statistics thread signal unblocking failed with error %d", s);

    thread_created = 1;

    return;
}

void cleanup_stats() {

    exit_stats_thread();

    if (stats != NULL) {
        free(stats);
        stats = NULL;
    }
}

void exit_stats_thread() {
    int s;
    void *retval;

    if (!thread_created) return;

    s = pthread_cancel(thread);
    if (s != 0)
        LOG_WARN("Statistics thread cancellation failed with error %d", s);

    s = pthread_join(thread, &retval);
    if (s != 0)
        LOG_WARN("Statistics thread join failed with error %d", s);

    if (retval != PTHREAD_CANCELED)
        LOG_WARN("Statistics thread exit value was unexpected");

    thread_created = 0;

    s = pthread_mutex_destroy(&stats_lock);
    if (s != 0)
        LOG_WARN("Statistcs thread mutex destroy failed with error %d", s);

    return;
}

void *run_stats (void *args) {
    struct thread_args *thread_args = (struct thread_args *) args;

    while (1) {
        sleep(thread_args->interval);
        display_stats(thread_args->printable);
    }

    return (void *) 0;
}


void init_udp_buffers(int printable)
{
    int i;
    struct sockaddr_in dest;
    memset (&udp_buffer, 0, sizeof(udp_buffer));

    bzero(&dest, sizeof(struct sockaddr_in));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
    udp_buffer.dest = dest;
    udp_buffer.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    udp_buffer.printable = printable;

    for(i = 0; i < UDP_BUFF_COUNT; i++) {
        char *p = (char *)malloc(UDP_BUFF_SIZE);
        if(NULL == p) {
            exit(0);
        }
        udp_buffer.iov[i].iov_base = p;
    }
}

int send_udp_buffer()
{
    struct msghdr mh;
    int rc;

    if(udp_buffer.idx <= 1) {
        return 0;
    }
    if(udp_buffer.printable) {
        return 0;
    }

    memset(&mh, 0, sizeof(mh));
    mh.msg_name = (caddr_t) &udp_buffer.dest;
    mh.msg_namelen = sizeof(struct sockaddr_in);
    mh.msg_iov = udp_buffer.iov;
    mh.msg_iovlen = udp_buffer.idx - 1;

    rc = sendmsg(udp_buffer.sockfd, &mh, 0);
    if(rc < 0) {
        printf("sendmsg error : %s\n", strerror(errno));
    }
    return rc;
}

void send_remain()
{
    struct udp_buffer *buffer = &udp_buffer;

    if(udp_buffer.printable) {
        return;
    }

    if(buffer->idx > 1) {
        send_udp_buffer();
        buffer->idx = 0;
        buffer->used = 0;
    }
}

void send_report(struct uri_stats *node, time_t time)
{
    int len;
    struct udp_buffer *buffer = &udp_buffer;
    struct iovec *iov;
    char addr[INET6_ADDRSTRLEN];

    if(buffer->idx == 0 && buffer->printable == 0) {
        iov = &buffer->iov[buffer->idx];
        len = sprintf(iov->iov_base, "%s", MAGIC);
        buffer->idx++;
        buffer->used = len;
        iov->iov_len = len;
    }

    iov = &buffer->iov[buffer->idx];
    addr[0] = 0;
    inet_ntop(AF_INET, &node->host, addr, sizeof(addr));
    len = snprintf(iov->iov_base, UDP_BUFF_SIZE, 
                   "URL ip:%s port:%d uri:%s rps:%d rep:%f in:%ld out:%ld timestamp:%ld timeout:%lu\r\n",
                   addr, node->port, node->uri, node->rps, node->rep, node->in_datalen, node->out_datalen, time, node->timeout);
    iov->iov_len = len;

    if (buffer->printable) {
        printf("%s", (char *)iov->iov_base);
        return;
    }

    buffer->idx++;
    if ((buffer->used + len) > UDP_BUFF_SIZE || buffer->idx >= UDP_BUFF_COUNT) {
        send_udp_buffer();
        buffer->idx = 0;
        buffer->used = 0;
    }
    else {
        buffer->used += len;
    }
}

void display_stats(int printable) {
    time_t now;
    float time_used = 0;
    unsigned int delta, rps = 0;
    int i;
    struct uri_stats *node, *prev, *garbage;

    if (stats == NULL) return;

    if(!init) {
        init_udp_buffers(printable);
        init = 1;
    }
    if (thread_created)
        pthread_mutex_lock(&stats_lock);

    now = time(NULL);
    recycle_request(now);

    for (i = 0; i < HASHSIZE; i++) {
        //int tmp = 0;

        node = stats[i];
        prev = NULL;

        while (node != NULL) {
            //tmp++;
            delta = now - node->first_packet;
            rps = 0;
            time_used = 0;
            if (delta > 0) {
                rps = (unsigned int) ceil(node->count / (float) delta);
            }
            if(node->rep_count) {
                time_used = node->time_used /(float)node->rep_count;
            }
            if(rps) {
                node->rps = rps;
                if(time_used) {
                    node->rep = time_used/1000000;
                    //node->in_datalen = node->in_datalen * 1000000 / time_used;
                    //node->out_datalen = node->out_datalen * 1000000 / time_used;
                }
                send_report(node, now);
                node->first_packet = 0;
                node->count = 0;
                // reset stats
                if (node->rep_count) {
                    node->time_used = 0;
                    node->rep_count = 0;
                    node->timeout = 0;
                    node->in_datalen = 0;
                    node->out_datalen = 0;
                }
            }
            else if(node->users == 0
                    && node->last_packet != 0 
                    && now > node->last_packet + 10) {
                if (prev == NULL) {
                    stats[i] = node->next;
                }
                else {
                    prev->next = node->next;
                }
                garbage = node;
                node = node->next;
                put_node(garbage);
                continue;
            }
            prev = node;
            node = node->next;
#if 0
            if(tmp > 100) {
                printf("catch you!!!!!!!!\n");
                break;
            }
#endif
        }
    }
    send_remain();
    if (thread_created)
        pthread_mutex_unlock(&stats_lock);

    return;
}

void remove_request(struct uri_request *request)
{
    struct uri_request *next, **pprev;

    pprev = request->pprev;
    next = request->next;
    *pprev = next;
    if(next)
      next->pprev = pprev;
}

void add_request(struct uri_record *record, struct timeval tv, struct uri_stats *node)
{
    struct uri_request *request, *p;
    int hashval;
    p = find_request(record);
    if(p != NULL) {
        return;
    }
    request = alloc_uri_request();
    request->record = *record;
    /* IMPORTANT!! USE  node's URI */
    request->record.uri = node->uri;
    request->timestamp = tv;
    request->stat = node;
    node->users++;
    /* add it into hash table */
    hashval = hash_request(record);
    if(requests[hashval]) requests[hashval]->pprev = &request->next;
    request->pprev = &requests[hashval];
    request->next = requests[hashval];
    requests[hashval] = request;
    /* recycle queue */
    request->next_req = NULL;
    request->pprev_req = requests_queue_tail;
    *requests_queue_tail = request;
    requests_queue_tail = &(request->next_req);
}

void recycle_request(time_t t)
{
    struct uri_request *request, *tmp;
    int count = 1000;
    struct timeval tv = {0};
    //float time_used=0;
    gettimeofday(&tv, NULL);
    request = requests_queue.next_req;
    while(count > 0 && request != NULL) {
        struct uri_stats *uri = request->stat;
        if(t > request->timestamp.tv_sec + 300) {
#if 0
            time_used = (tv.tv_sec - request->timestamp.tv_sec) * 1000000 + (tv.tv_usec - request->timestamp.tv_usec);
            uri->time_used += time_used;
            uri->rep_count++;
#endif
            uri->timeout++;
            if(see_recycle) {
                printf("recycle: uri:%s, port:%u, seq:%u, ack:%u flag:%u\n", 
                       request->record.uri, request->record.dst_port,
                       request->record.seq, request->record.ack, request->flag);
            }
            tmp = request->next_req;
            remove_from_recycle(request);
            remove_request(request);
            free_uri_request(request);
            //count--;
            request = tmp;
        }
        else {
            break;
        }
    }
    /* AT LAST ?*/
    if (request == NULL) {
        requests_queue_tail = &(requests_queue.next_req);      
    }
}

void update_request_datalen(struct uri_record *record)
{
    struct uri_request *req;
    //printf("begin find\n");
    int hashval = hash_request(record);
    for ( req = requests[hashval]; req != NULL; req = req->next) {
        /* request */
        if(req->record.src_port == record->src_port
           && memcmp(&req->record.src_addr, &record->src_addr, sizeof(struct in_addr)) == 0) {
            if(req->stat) {
                req->stat->in_datalen += record->tcp_datalen;
            }
            return;
        }
        /* response */
        if(req->record.src_port == record->dst_port
           && memcmp(&req->record.src_addr, &record->dst_addr, sizeof(struct in_addr)) == 0) {
            if(req->stat) {
                req->stat->out_datalen += record->tcp_datalen;
            }
            return;
        }
    }

}

struct uri_request *find_request(struct uri_record *record)
{
    struct uri_request *req;
    //printf("begin find\n");
    int hashval = hash_request(record);
    for ( req = requests[hashval]; req != NULL; req = req->next) {
        /* request */
        if(record->uri) {
            if(req->record.seq == record->seq 
               && req->record.src_port == record->src_port
               && memcmp(&req->record.src_addr, &record->src_addr, sizeof(struct in_addr)) == 0)
                return req;
        }
        /* response */
        else {
            if(req->record.ack == record->seq 
               && req->record.src_port == record->dst_port
               && memcmp(&req->record.src_addr, &record->dst_addr, sizeof(struct in_addr)) == 0)
                return req;
#if 0
            if(req->record.ack != record->seq && req->flag == 1
               && req->record.src_port == record->dst_port
               && memcmp(&req->record.src_addr, &record->dst_addr, sizeof(struct in_addr)) == 0)
                printf("PPS uri:%s req_ack:%u res_seq:%u port:%u svr_port: %u\n", req->record.uri, req->record.ack, record->seq, record->dst_port, record->src_port);
#endif
        }
    }

    return NULL;
}

struct uri_request *find_response_noseq(struct uri_record *record)
{
    struct uri_request *req;
    int hashval = hash_request(record);
    for ( req = requests[hashval]; req != NULL; req = req->next) {
        if(req->record.src_port == record->dst_port
           && memcmp(&req->record.src_addr, &record->dst_addr, sizeof(struct in_addr)) == 0) {
            return req;
        }
    }

    return NULL;
}

struct uri_request *find_response(struct uri_record *record)
{
    struct uri_request *req;
    int hashval = hash_request(record);
    for ( req = requests[hashval]; req != NULL; req = req->next) {
        if(req->record.ack == record->seq 
           && req->record.src_port == record->dst_port
           && memcmp(&req->record.src_addr, &record->dst_addr, sizeof(struct in_addr)) == 0)
            return req;
    }

    return NULL;
}


void remove_from_recycle(struct uri_request *request)
{
    struct uri_request **pprev, *next;

    next = request->next_req;
    pprev = request->pprev_req;
    *pprev = next;
    if(next) {
        next->pprev_req = request->pprev_req;
    }
    /* update the tail */
    if (requests_queue_tail == &(request->next_req)) {
        requests_queue_tail = pprev;
    }

    request->next_req = NULL;
}

void update_request_continued(struct uri_record *record, struct timeval tv)
{
    struct uri_request *request;

    if (thread_created)
        pthread_mutex_lock(&stats_lock);

    request = find_request(record);
    if(request == NULL) {
        goto LAST;
    }
    if(see_recycle) {
        printf("request continue stat_uri:%s\n", request->stat->uri);
    }
    request->flag = 1;
    /* forge the request */
    request->record.ack = record->seq + record->tcp_datalen;
    /* request->record.seq = record->ack; */
LAST:
    if (thread_created)
        pthread_mutex_unlock(&stats_lock);    
}

void fin_response_(struct uri_request *request)
{
    if(request == NULL) {
        return;
    }

    /* remove it from hash table */
    remove_request(request);
    remove_from_recycle(request);

    free_uri_request(request);
}

void fin_response(struct uri_record *record)
{
    struct uri_request *request;

    if (thread_created)
        pthread_mutex_lock(&stats_lock);

    request = find_response_noseq(record);
    fin_response_(request);

    if (thread_created)
        pthread_mutex_unlock(&stats_lock);
}

int finish_request(struct uri_record *record, struct timeval tv, int is_fin)
{
    struct uri_request *request;
    struct uri_stats *uri;
    float time_used=0;
    int err = 0;
    if (thread_created)
        pthread_mutex_lock(&stats_lock);

    request = find_response(record);
    if(request == NULL) {
        err = -1;
        goto LAST;
    }
    if(see_recycle && request->flag) {
        printf("continued found stat_uri:%s record_uri:%s \n", request->stat->uri, request->record.uri);
    }
    request->flag = 0;
    uri = request->stat;

    if(uri == NULL) {
        err = -1;
        goto LAST;
    }
    time_used = (tv.tv_sec - request->timestamp.tv_sec) * 1000000 + (tv.tv_usec - request->timestamp.tv_usec);
    uri->time_used += time_used;
    uri->rep_count++;
    uri->out_datalen += record->tcp_datalen;
#if 0
    printf("req.ack:%u res.seq:%u port1:%u port2:%u time_used %f count:%d\n", 
	request->record.ack, record->seq, 
        request->record.src_port, record->dst_port,
	uri->time_used/1000000, uri->rep_count);
#endif 

LAST:
    if(is_fin) {
        fin_response_(request);
    }
    if (thread_created)
        pthread_mutex_unlock(&stats_lock);
    return err;
}

int update_stats(struct uri_record *record, struct timeval tv) 
{
    struct uri_stats *node;
    unsigned int hashval;

    if ((record->uri == NULL) || (stats == NULL)) return -1;

    if (thread_created)
        pthread_mutex_lock(&stats_lock);

    if ((node = get_uri(record)) == NULL) {
        node = get_node();
        memset(node, 0, sizeof(*node));
        node->port = record->dst_port;
        node->host = record->dst_addr;
        /* used for testing */
        debug_ascii(record->uri, "Entry");
        str_copy(node->uri, record->uri, MAX_URI_LEN);
        //snprintf(node->uri, MAX_URI_LEN, record->uri);

        hashval = hash_uri(record);
#ifdef DEBUG
        ASSERT((hashval >= 0) && (hashval < HASHSIZE));
#endif
        node->first_packet = tv.tv_sec;
        /* Link node into hash */
        node->next = stats[hashval];
        stats[hashval] = node;
    }

    if (node->first_packet == 0) {
        node->first_packet = tv.tv_sec;
    }
    node->last_packet = tv.tv_sec;
    node->count++;
    node->total++;
    node->in_datalen += record->tcp_datalen;
    add_request(record, tv, node);
    if (thread_created)
        pthread_mutex_unlock(&stats_lock);

    return 0;
}

struct uri_stats *get_uri(struct uri_record *record) {
    struct uri_stats *node;
    for (node = stats[hash_uri(record)]; node != NULL; node = node->next) {
        //printf("str:%s uri:%s\n", str, node->uri);
        if (str_compare(record->uri, node->uri) == 0 &&
            record->dst_port == node->port &&
            memcmp(&record->dst_addr, &node->host, sizeof(struct in_addr)) == 0)  {
	    //printf("found\n");
	    return node;
        }
    }
    return NULL;
}

struct uri_stats *get_node()
{
    void *p = NULL;
#ifdef USE_SLAB
    hurd_slab_alloc(stats_slab, &p);
#else
    p = malloc(sizeof(struct uri_stats));
#endif
    node_count++;
    return p;
}

void put_node(struct uri_stats *node)
{
    strcpy(node->uri,"zzzzzz");
#ifdef USE_SLAB
    hurd_slab_dealloc(stats_slab, node);
#else
    free(node);
#endif
    node_count--;
}
