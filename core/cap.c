
#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <pcap.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include "error.h"
#include "tcp.h"
#include "stats.h"
#include "utils.h"

struct http_struct {
    struct  in_addr src_addr;
    struct  in_addr dst_addr;
    int src_port;
    int dst_port;
    u_int32_t seq;
    u_int32_t ack;
    u_int32_t tcp_datalen;
    char *method;
    char *request_uri;
    char *status_code;
    int direction;
    struct timeval timestamp;
};
#define REQUEST 1
#define RESPONSE 2
#define BUFF_SIZE 1024

int getopt(int, char * const *, const char *);
pcap_t *prepare_capture(char *interface, int promisc,  char *capfilter);
void set_link_header_offset(int header_type);
void open_outfiles();
void runas_daemon();
int have_request_method(const char *str);
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
char *parse_header_line(char *header_line);
int parse_request(char *header_line, struct http_struct *http);
int parse_response(char *header_line, struct http_struct *http);
void handle_signal(int sig);
void cleanup();
void print_stats();
void display_usage();

/* Program flags/options, set by arguments or config file */
static unsigned int parse_count = 0;
static int daemon_mode = 0;
static char *interface = NULL;
static char *capfilter = NULL;
static char *use_outfile = NULL;
static int set_promisc = 1;
static char *pid_filename = NULL;
static int use_stats = 0;
static int stats_interval = 1;
static int force_flush = 0;
int quiet_mode = 0;               /* Defined as extern in error.h */
int use_syslog = 0;               /* Defined as extern in error.h */

static pcap_t *pcap_hnd = NULL;   /* Opened pcap device handle */
static char *buf = NULL;
static unsigned int num_parsed = 0;      /* Count of fully parsed HTTP packets */
static time_t start_time = 0;      /* Start tick for statistics calculations */
static int link_header_offset = 0;
static char default_capfilter[] = "";//"tcp port 80 or 8080";

char *methods[] = {"GET", "POST"};

int have_request_method(const char *str)
{
    int i;
    int cmp;
    if (strlen(str) == 0)
        return 0;

    for(i = 0; i < sizeof(methods)/sizeof(methods[0]); i++) {
        cmp = strncasecmp(str, methods[i], strlen(methods[i]));
        if (cmp == 0) {
            return 1;
        }
    }

    return 0;
}



/* Find and prepare ethernet device for capturing */
pcap_t *prepare_capture(char *interface, int promisc, char *capfilter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_hnd;
    char *dev = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program filter;


    /* Starting live capture, so find and open network device */
    if (!interface) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
            LOG_DIE("Cannot find a valid capture device: %s", errbuf);
    } else {
        dev = interface;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) net = 0;

    pcap_hnd = pcap_open_live(dev, BUFF_SIZE, promisc, 0, errbuf);
    if (pcap_hnd == NULL)
        LOG_DIE("Cannot open live capture on '%s': %s", dev, errbuf);

    set_link_header_offset(pcap_datalink(pcap_hnd));

    /* Compile capture filter and apply to handle */
    if (pcap_compile(pcap_hnd, &filter, capfilter, 0, net) == -1)
        LOG_DIE("Cannot compile capture filter '%s': %s", capfilter, pcap_geterr(pcap_hnd));

    if (pcap_setfilter(pcap_hnd, &filter) == -1)
        LOG_DIE("Cannot apply capture filter: %s", pcap_geterr(pcap_hnd));

    pcap_freecode(&filter);
    return pcap_hnd;
}

void set_link_header_offset(int header_type) {

    switch (header_type) {
    case DLT_EN10MB:
        link_header_offset = 14;
        break;
    case DLT_NULL:
        link_header_offset = 4;
        break;
    case DLT_RAW:
        link_header_offset = 0;
        break;
    default:
        LOG_DIE("Unsupported datalink type: %s", pcap_datalink_val_to_name(header_type));
        break;
    }

    return;
}


/* Run program as a daemon process */
void runas_daemon() {
    int child_pid;
    FILE *pid_file;

    if (getppid() == 1) return; /* We're already a daemon */

    fflush(NULL);

    child_pid = fork();
    if (child_pid < 0) LOG_DIE("Cannot fork child process");
    if (child_pid > 0) exit(0);

    /* Configure default output streams */
    dup2(1,2);
    close(0);
    if (freopen(NULL_FILE, "a", stderr) == NULL)
        LOG_DIE("Cannot reopen stderr to '%s'", NULL_FILE);

    /* Assign new process group for child */
    if (setsid() == -1)
        LOG_WARN("Cannot assign new session for child process");

    umask(022); /* Reset file creation mask */
    if (chdir("/") == -1)
        LOG_DIE("Cannot change run directory to '/'");

    /* Create PID file */
    if (pid_filename[0] != '/')
        LOG_WARN("PID file path is not absolute and may be inaccessible after daemonizing");
    if ((pid_file = fopen(pid_filename, "w"))) {
        fprintf(pid_file, "%d", getpid());
        fclose(pid_file);
    } else {
        LOG_WARN("Cannot open PID file '%s'", pid_filename);
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTERM, &handle_signal);

    fflush(NULL);

    return;
}
void print_http(struct http_struct *http_struct, struct timeval tv)
{
    char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
    struct tm *pkt_time;
    char ts[128];

    pkt_time = localtime((time_t *) &tv.tv_sec);
    strftime(ts, 127, "%Y-%m-%d %H:%M:%S", pkt_time);
    inet_ntop(AF_INET, &http_struct->src_addr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &http_struct->dst_addr, daddr, sizeof(daddr));
    printf("%s.%06ld seq %u ack %u src_ip:%s src_port:%d dst_ip:%s dst_port:%d method:%s %s\n", ts, tv.tv_usec,
           http_struct->seq, http_struct->ack, saddr, http_struct->src_port, daddr, http_struct->dst_port,
           http_struct->method, (http_struct->direction==REQUEST)?http_struct->request_uri:http_struct->status_code);
}

void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
    char *header_line;
    int is_request = 0, is_response = 0;

    const struct ip_header *ip;
    const struct tcp_header *tcp;
    const char *data;
    int ip_headlen, tcp_headlen, data_len, family;
    struct http_struct http_struct;
    int is_fin = 0;

    memset(&http_struct, 0, sizeof(struct http_struct));

    ip = (struct ip_header *) (pkt + link_header_offset);

    switch (IP_V(ip)) {
    case 4: family = AF_INET; break;
    default: return;
    }
    ip_headlen = IP_HL(ip) * 4;
    if (ip_headlen < 20) return;
    if (ip->ip_p != IPPROTO_TCP) return;

    tcp = (struct tcp_header *) ((char *)ip + ip_headlen);
    tcp_headlen = TH_OFF(tcp) * 4;
    is_fin = (tcp->th_flags & TH_FIN);
    if (tcp_headlen< 20) return;
    data = (char *)tcp + tcp_headlen;
    data_len = (header->caplen - (link_header_offset + ip_headlen + tcp_headlen));
    if (data_len < 0) {
        return;
    }
    http_struct.tcp_datalen = ntohs(ip->ip_len) - ip_headlen - tcp_headlen;

    http_struct.src_addr = ip->ip_src;
    http_struct.dst_addr = ip->ip_dst;

    http_struct.src_port = ntohs(tcp->th_sport);
    http_struct.dst_port = ntohs(tcp->th_dport);

    http_struct.seq = ntohl(tcp->th_seq);
    http_struct.ack = ntohl(tcp->th_ack);
    /* capture timestamp */
    http_struct.timestamp = header->ts;

    if (0 == http_struct.tcp_datalen) {
        struct uri_record record;
        record.uri = http_struct.request_uri;
        record.src_port = http_struct.src_port;
        record.src_addr = http_struct.src_addr;
        record.dst_port = http_struct.dst_port;
        record.dst_addr = http_struct.dst_addr;
        record.ack = http_struct.ack;
        record.seq = http_struct.seq;
        if(is_fin) {
            fin_response(&record);
        }
        return;
    }

    if (have_request_method(data)) {
        is_request = 1;
    } else if (strncmp(data, "HTTP/", strlen("HTTP/")) == 0) {
        is_response = 1;
    } else {
        //return;
    }

    if (data_len >= BUFF_SIZE) data_len = BUFF_SIZE-1;
    memcpy(buf, data, data_len);
    /*TODO: tcp data fragment */
    if(data_len > 2) {
        buf[data_len-1] = '\n';
    }
    buf[data_len] = '\0';
    if ((header_line = parse_header_line(buf)) == NULL) return;
    if (is_request) {
        if (parse_request(header_line, &http_struct)) return;
    }
    else if (is_response) {
        if (parse_response(header_line, &http_struct)) return;
    }

    if(http_struct.request_uri) {
        char *p = strstr(http_struct.request_uri, "?");
        if(p) *p = '\0';
    }
    if (use_stats) {
        int err = -1;
        struct uri_record record;
        record.uri = http_struct.request_uri;
        record.src_port = http_struct.src_port;
        record.src_addr = http_struct.src_addr;
        record.dst_port = http_struct.dst_port;
        record.dst_addr = http_struct.dst_addr;
        record.ack = http_struct.ack;
        record.seq = http_struct.seq;
        record.tcp_datalen = http_struct.tcp_datalen;

        if (http_struct.request_uri) {
            // record the request
            err = update_stats(&record, header->ts);
        }
        else {
            if(http_struct.status_code && 
               strcmp(http_struct.status_code, "100") == 0) {
                update_request_continued(&record, header->ts);
                /* printf("continue req ack:%u seq:%u datalen:%u \n",record.ack,record.seq,record.tcp_datalen); */
            }
            else {
                // record the response
                err = finish_request(&record, header->ts, is_fin);
                is_fin = 0;
            }
        }
        if(err < 0) {
            // update in/out data_len
            update_request_datalen(&record);
        }
        if(is_fin) {
            fin_response(&record);
        }
    }

    if (!use_stats) {
        print_http(&http_struct, header->ts);
    }

    num_parsed++;
    if (parse_count && (num_parsed >= parse_count))
        pcap_breakloop(pcap_hnd);

    return;
}

/* Tokenize a HTTP header into lines; the first call should pass the string
   to tokenize, all subsequent calls for the same string should pass NULL */
char *parse_header_line(char *header_line) {
    static char *pos;
    char *tmp;

    if (header_line) pos = header_line;

    /* Search for a '\n' line terminator, ignoring a leading
       '\r' if it exists (per RFC2616 section 19.3) */
    tmp = strchr(pos, '\n');
    if (!tmp) return NULL;
    *tmp = '\0';
    if (*(tmp - 1) == '\r') *(--tmp) = '\0';

    if (tmp == pos) return NULL; /* Reached the end of the header */

    header_line = pos;
    /* Increment past the '\0' character(s) inserted above */
    if (*tmp == '\0') {
        tmp++;
        if (*tmp == '\0') tmp++;
    }
    pos = tmp;

    return header_line;
}

int analyse_EPG_action(char *args, char *uri)
{
    char *start, *end;

    if(strcmp(uri, "/cgi-bin/epg_index.fcgi") != 0) {
        return -1;
    }

    start = strstr(args, "action=");
    if(NULL == start) {
        return -1;
    }
    // 7 is strlen("action=")
    start += 7;
    end = strchr(start, '%');
    if(end) {
        *end = '\0';
    }
    end = strchr(start, '&');
    if(end) {
        *end = '\0';
    }
    strcat(uri, "_");
    strcat(uri, start);

    return 0;
}

int parse_request(char *header_line, struct http_struct *http_struct) {
    char *method, *request_uri, *http_version;
    char *p;
#ifdef DEBUG
    ASSERT(header_line);
    ASSERT(strlen(header_line) > 0);
#endif
    /* format: metho uri http_version */
    method = header_line;
    if ((request_uri = strchr(method, ' ')) == NULL)
        return 1;
    *request_uri++ = '\0';
    while (isspace(*request_uri))
        request_uri++;
    /* TODO: tcp data fregment!! */
    if ((http_version = strchr(request_uri, ' ')) == NULL) {
#if 1
        if ((http_version = strchr(request_uri, '?')) != NULL) {
            *http_version = '\0';
            /* do analysis EPG action */
            http_version++;
            analyse_EPG_action(http_version, request_uri);
            goto LAST;
        }
#endif
        return 1;
    }
    // do xxxx?args=xxx
    if ((p = strchr(request_uri, '?')) != NULL) {
        *p = '\0';
        /* do analysis EPG action */
        analyse_EPG_action(p+1, request_uri);
    }
    *http_version++ = '\0';
    while (isspace(*http_version))
        http_version++;

    if (strncmp(http_version, HTTP_STRING, strlen(HTTP_STRING)) != 0)
        return 1;
LAST:
    http_struct->method = method;
    http_struct->request_uri = request_uri;
    http_struct->direction = REQUEST;

    return 0;
}

int parse_response(char *header_line, struct http_struct *http_struct) {
    char *http_version, *status_code, *reason_phrase;

#ifdef DEBUG
    ASSERT(header_line);
    ASSERT(strlen(header_line) > 0);
#endif
    /* format: http_version status_code  */
    http_version = header_line;

    if ((status_code = strchr(http_version, ' ')) == NULL)
        return 1;
    *status_code++ = '\0';
    while (isspace(*status_code))
        status_code++;

    if ((reason_phrase = strchr(status_code, ' ')) == NULL)
        return 1;
    *reason_phrase++ = '\0';
    while (isspace(*reason_phrase))
        reason_phrase++;
    http_struct->method = "RESPONSE";
    http_struct->status_code = status_code;
    http_struct->direction = RESPONSE;

    return 0;
}

/* Handle signals for clean reloading or shutdown */
void handle_signal(int sig) {

#ifdef DEBUG
    ASSERT(sig > 0);
#endif

    switch (sig) {
    case SIGHUP:
    case SIGINT:
        LOG_PRINT("Caught SIGINT, shutting down...");
        print_stats();
        cleanup();
        break;
    case SIGTERM:
        LOG_PRINT("Caught SIGTERM, shutting down...");
        print_stats();
        cleanup();
        break;
    default:
        LOG_WARN("Ignoring unknown signal '%d'", sig);
        return;
    }

    exit(sig);
}


void cleanup() {
    if (pcap_hnd) pcap_breakloop(pcap_hnd);
    if (use_stats) cleanup_stats();

    fflush(NULL);
    if (buf) free(buf);

    if (daemon_mode) remove(pid_filename);
    if (pcap_hnd) pcap_close(pcap_hnd);

    return;
}

void print_stats() {
    struct pcap_stat pkt_stats;
    float run_time;
    extern int node_count;
    extern int request_count;
    if (use_stats)
        display_stats(1);

    if (pcap_stats(pcap_hnd, &pkt_stats) != 0) {
        WARN("Cannot obtain packet capture statistics: %s", pcap_geterr(pcap_hnd));
        return;
    }

    LOG_PRINT("%u packets received, %u packets dropped, %u http packets parsed", \
              pkt_stats.ps_recv, pkt_stats.ps_drop, num_parsed);

    run_time = (float) (time(0) - start_time);
    if (run_time > 0) {
        LOG_PRINT("%0.1f packets/min, %0.1f http packets/min", \
                  ((pkt_stats.ps_recv * 60) / run_time), ((num_parsed * 60) / run_time));
    }
    LOG_PRINT("allocated stat node:%d request:%d\n", node_count, request_count);
    return;
}


void display_usage() {

    printf("Usage: %s [ -dhps ] [ -i device ] \n"
           "          [ -n count ] \n"
           "          [ -t seconds] [ 'expression' ]\n\n", PROG_NAME);

    printf("   -d           run as daemon\n"
           "   -h           print this help information\n"
           "   -i device    listen on this interface\n"
           "   -n count     set number of HTTP packets to parse\n"
           "   -p           disable promiscuous mode\n"
           "   -s           stats mode\n"
           "   -S           stats mode, print stats result\n"
           "   -r           stats mode, print stats result & recycle ..\n"
           "   -t seconds   specify the display interval for update statistics\n"
           "   expression   specify a bpf-style capture filter\n\n");

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int opt;
    extern char *optarg;
    extern int optind;
    int loop_status;

    signal(SIGHUP, &handle_signal);
    signal(SIGINT, &handle_signal);
    if(argc < 2) {
        display_usage();
        return -1;
    }
    /* Process command line arguments */
    while ((opt = getopt(argc, argv, "dFhpi:n:o:st:Sr")) != -1) {
        switch (opt) {
        case 'd': daemon_mode = 1; use_syslog = 1;
            break;
        case 'F': force_flush = 1;
            break;
        case 'h': display_usage();
            break;
        case 'i': interface = optarg;
            break;
        case 'n': parse_count = atoi(optarg);
            break;
        case 'o': use_outfile = optarg;
            break;
        case 's': use_stats = 1;
            break;
        /* print stats result */
        case 'S': use_stats = 2;
            break;
        /* print stats result  and recycle */
        case 'r': use_stats = 3;
            break;
        case 't': stats_interval = atoi(optarg);
            break;
        default: display_usage();
        }
    }


    if (parse_count < 0)
        LOG_DIE("Invalid -n value, must be 0 or greater");

    if (stats_interval < 1)
        LOG_DIE("Invalid -t value, must be 1 or greater");

    if (argv[optind] && *(argv[optind])) {
        capfilter = argv[optind];
    } else {
        capfilter = default_capfilter;
    }

    if (force_flush) {
        if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
            LOG_WARN("Cannot disable buffering on stdout");
    }

    pid_filename = "/tmp/httpcap.pid";

    pcap_hnd = prepare_capture(interface, set_promisc, capfilter);

    if (daemon_mode) runas_daemon();

    if ((buf = malloc(BUFF_SIZE + 1)) == NULL)
        LOG_DIE("Cannot allocate memory for packet data buffer");
    if (use_stats) {
        init_stats(stats_interval, use_stats-1);
    }
    start_time = time(0);
    loop_status = pcap_loop(pcap_hnd, -1, &parse_http_packet, NULL);
    if (loop_status == -1) {
        LOG_DIE("Problem reading packets from interface: %s", pcap_geterr(pcap_hnd));
    } else if (loop_status == -2) {
        PRINT("Loop halted, shutting down...");
    }

    print_stats();
    cleanup();

    return loop_status == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
