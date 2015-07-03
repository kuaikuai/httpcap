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
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "tcp.h"
#include "error.h"
void set_link_header_offset(int header_type);
int use_syslog = 1;
static pcap_t *pcap_hnd = NULL;   /* Opened pcap device handle */
static char *buf = NULL;
static int link_header_offset = 0;

char *methods[] = {"GET ", "POST "};
int str_is_ascii(char *str, int len);
char *word[] = {"sagnon","signwn","kignon",
                "khared","repojt_terminal",
                "regisler","ehg_index",
                "eqg_index","repost_terminal"};

void debug_ascii(char *uri, int len, char *info)
{
    int i;
    char tmp[256];
#if 0
    /* used for testing */
    if (!str_is_ascii(uri, len)) {
        snprintf(tmp, sizeof(tmp)-1, "%s found no ascii %s", info, uri);
        LOG(tmp);
        return;
    }
#endif
    for(i = 0; i < sizeof(word)/sizeof(word[0]); i++) {
        if(strstr(uri, word[i]) != NULL) {
            snprintf(tmp, sizeof(tmp)-1, "%s found sample %s", info, uri);
            LOG(tmp);
        }
    }
}



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

    pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, 50, errbuf);
    if (pcap_hnd == NULL)
        LOG_DIE("Cannot open live capture on '%s': %s", dev, errbuf);

    set_link_header_offset(pcap_datalink(pcap_hnd));

    /* Compile capture filter and apply to handle */
    if (pcap_compile(pcap_hnd, &filter, capfilter, 0, net) == -1)
        LOG_DIE("Cannot compile capture filter '%s': %s", capfilter, pcap_geterr(pcap_hnd));

    if (pcap_setfilter(pcap_hnd, &filter) == -1)
        LOG_DIE("Cannot apply capture filter: %s", pcap_geterr(pcap_hnd));

    /*pcap_freecode(&filter);*/
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

void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
    int is_request = 0, is_response = 0;

    const struct ip_header *ip;
    const struct tcp_header *tcp;
    const char *data;
    int ip_headlen, tcp_headlen, data_len, family;

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
    if (tcp_headlen< 20) return;

    data = (char *)tcp + tcp_headlen;
    data_len = (header->caplen - (link_header_offset + ip_headlen + tcp_headlen));
    if (data_len <= 0) return;

    if (have_request_method(data)) {
        is_request = 1;
    } else if (strncmp(data, "HTTP/", strlen("HTTP/")) == 0) {
        is_response = 1;
    } else {
        return;
    }

    if (data_len > BUFSIZ) data_len = BUFSIZ;
    memcpy(buf, data, data_len);
    buf[data_len-1] = '\0';

    if (is_request) {
        char *p = strchr(buf, '?');
        if(p) *p = '\0';
        debug_ascii(buf, data_len, "TEST0" );
    }
    else if (is_response) {
    }

    return;
}

int str_is_ascii(char *str, int len) {
    int count = 0;
    while (*str != '\0') {
        unsigned char ch = *str++;
        count++;
        if(count > 128 || count >= len) {
            break;
        }
        if (ch >= 0x80) {
            return 0;
        }
    }
    return 1;
}



void capture_packet(pcap_t *pd)
{
    int len;
    char *ptr = NULL;
    struct pcap_pkthdr hdr;
    for(;;) {
        while((ptr = (char *)pcap_next(pd,&hdr)) == NULL);
        parse_http_packet(NULL, &hdr, ptr);
    }
}




int main(int argc,char **argv)
{

    daemon(0,0);

    buf = malloc(BUFSIZ + 1);
    if(NULL == buf) {
        printf("buf null");
        exit(1);
    }
    pcap_hnd = prepare_capture("eth2", 1, "");
    capture_packet(pcap_hnd);
    //pcap_loop(pcap_hnd, -1, &parse_http_packet, NULL);

    return 0;
}
