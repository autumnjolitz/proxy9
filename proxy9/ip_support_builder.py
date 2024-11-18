from cffi import FFI

ffibuilder = FFI()
ffibuilder.cdef("""

int getifaddrs(struct ifaddrs **ifap);

void freeifaddrs(struct ifaddrs *ifp);

struct sockaddr_un {
       uint8_t  sun_len;
       uint8_t  sun_family;
       char    sun_path[...];
       ... ;
};


 struct sockaddr {
     uint8_t sa_len;
     uint8_t sa_family; /* address family ?? */
     char sa_data[]; /* socket data */
     ... ;
 };

 struct sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family; /* AF_INET */
    uint16_t sin_port;
    char sin_addr[4];
    uint8_t  sin_zero[8];
    ... ;
 };

struct sockaddr_in6 {
    uint8_t     sin6_len;
    uint8_t     sin6_family; /* AF_INET6 */
    uint16_t    sin6_port;
    uint32_t    sin6_flowinfo;
    char        sin6_addr[16];
    uint32_t    sin6_scope_id;
    ... ;
};

struct sockaddr_dl {
    uint8_t  sdl_len;        /* Total length of sockaddr */
    uint8_t  sdl_family;     /* AF_LINK */
    unsigned short sdl_index;      /* if != 0, system given index for interface */
    uint8_t  sdl_type;       /* interface type */
    uint8_t  sdl_nlen;       /* interface name length, no trailing 0 reqd. */
    uint8_t  sdl_alen;       /* link level address length */
    uint8_t  sdl_slen;       /* link layer selector length */
    char    sdl_data[...];   /* minimum work area, can be larger;
                             *  contains both if name and ll address */
     ... ;
};


 struct ifaddrs {
     struct ifaddrs   *ifa_next;         /* Pointer to next struct */
     char             *ifa_name;         /* Interface name */
     unsigned int     ifa_flags;        /* Interface flags */
     struct sockaddr  *ifa_addr;         /* Interface address */
     struct sockaddr  *ifa_netmask;      /* Interface netmask */
     struct sockaddr  *ifa_dstaddr;      /* P2P interface destination */
     void             *ifa_data;         /* Address specific data */
     ... ;
 };

typedef ... some_time_val;

struct if_data {
    uint8_t ifi_type;
    uint8_t ifi_physical;
    uint8_t ifi_addrlen;
    uint8_t ifi_hdrlen;

    uint32_t ifi_mtu;
    uint32_t ifi_metric;
    uint32_t ifi_baudrate;

    uint32_t ifi_ipackets;
    uint32_t ifi_ierrors;
    uint32_t ifi_opackets;
    uint32_t ifi_oerrors;
    uint32_t ifi_collisions;
    uint32_t ifi_ibytes;
    uint32_t ifi_obytes;
    uint32_t ifi_imcasts;
    uint32_t ifi_omcasts;
    uint32_t ifi_iqdrops;
    uint32_t ifi_noproto;
    void* ifi_lastchange;
    ...;
};

static const int IFT_OTHER;
static const int IFT_ETHER;
static const int IFT_ISO88023;
static const int IFT_ISO88024;
static const int IFT_ISO88025;
static const int IFT_ISO88026;
static const int IFT_FDDI;
static const int IFT_PPP;
static const int IFT_LOOP;
static const int IFT_SLIP;
static const int IFT_PARA;
static const int IFT_ATM;


static const int IFF_UP;
static const int IFF_BROADCAST;
static const int IFF_DEBUG;
static const int IFF_LOOPBACK;
static const int IFF_POINTOPOINT;
static const int IFF_RUNNING;
static const int IFF_NOARP;
static const int IFF_PROMISC;
static const int IFF_ALLMULTI;
static const int IFF_OACTIVE;
static const int IFF_SIMPLEX;
static const int IFF_LINK0;
static const int IFF_LINK1;
static const int IFF_LINK2;
static const int IFF_MULTICAST;
static const int IFF_NOTRAILERS;

void read_last_change_on(struct if_data *data, int64_t *tv_sec, int64_t* tv_usec);

""")
ffibuilder.set_source(
    "_ip_support",
    """
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>

#ifndef _TIME_T
#define _TIME_T
#include <machine/types.h> /* __darwin_time_t */
typedef __darwin_time_t         time_t;
typedef __darwin_useconds_t     useconds_t;
#endif  /* _TIME_T */
#ifndef __APPLE__
static const int IFF_PPROMISC;
static const int IFCAP_NETCONS;
static const int IFCAP_RXCSUM;
static const int IFCAP_TXCSUM;
#endif
#ifdef __APPLE__
    #ifndef IFF_NOTRAILERS
#define IFF_NOTRAILERS  0x20
    #endif
#endif

void read_last_change_on(struct if_data *data, int64_t *tv_sec, int64_t* tv_usec) {
    struct IF_DATA_TIMEVAL time = data->ifi_lastchange;
    *tv_sec = time.tv_sec;
    *tv_usec = time.tv_usec;
}

""",
)


def main():
    ffibuilder.compile(verbose=True)


if __name__ == "__main__":
    main()
