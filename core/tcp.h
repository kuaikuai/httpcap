
#ifndef _HAVE_TCP_H
#define _HAVE_TCP_H

#include <arpa/inet.h>
#include <netinet/in.h>

/* IP header */
struct ip_header {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* IPv6 header */
struct ip6_header {
        uint32_t ip6_vtcfl;             /* version << 4 | traffic class 8 | flow label >> 20 */
        u_short  ip6_plen;              /* payload length */
        u_char   ip6_nh;                /* next header */
        u_char   ip6_hl;                /* hop limit */
        struct   in6_addr ip_src,ip_dst; /* source and dest address */
};
#define IP6_V(ip6)              (((ip6)->ip6_vtcfl) >> 28)
#define IP6_TC(ip6)             ((((ip6)->ip6_vtcfl) >> 20) & 0x000000ff)
#define IP6_FL(ip6)             (((ip6)->ip6_vtcfl) & 0x000fffff)

/* IPv6 extension headers */
struct ip6_ext_header {
        u_char ip6_eh_nh;             /* next header */
        u_char ip6_eh_len;            /* length in 8-octet units, not including first 8-octets */
};

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

#endif /* ! _HAVE_TCP_H */
