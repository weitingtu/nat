/*
 * nftest.c
 * - demo program of netfilter_queue
 * - Patrick P. C. Lee
 *
 * - To run it, you need to be in root
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "checksum.h"
#include "net_print.h"
#include <map>
#include <set>
#include <vector>
#include <list>
#include <algorithm>
#include <numeric>

extern "C"
{
#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
#include <libnetfilter_queue/libnetfilter_queue.h>
}

pthread_mutex_t debug_lock = PTHREAD_MUTEX_INITIALIZER;

void _io_debug( const char* format, ... ) __attribute__( ( format( printf, 1, 2 ) ) );
void _io_debug( const char* format, ... )
{
#ifdef DEBUG
    pthread_mutex_lock( &debug_lock );
    printf( "<debug> " );
    va_list args;
    va_start( args, format );
    vprintf( format, args );
    va_end( args );
    pthread_mutex_unlock( &debug_lock );
#endif
}

#define io_debug( format, ... )   \
    { \
        _io_debug( format, ##__VA_ARGS__); \
    }

static int mask_int = 0;
static unsigned int local_mask = 0;

static int bucket_size = 2048;
static int fill_rate   = 2048;

static struct in_addr publicNetAddr;
static struct in_addr localNetAddr;

struct IpPort
{
    //u_int32_t saddr;
    //u_int32_t daddr;
    //u_int16_t source; /* source port */
    //u_int16_t dest;   /* destination port */

    u_int32_t addr;
    u_int16_t port;
};

struct IpPortCompare
{
    bool operator() ( const IpPort& l, const IpPort& r ) const
    {
        return l.addr < r.addr || ( l.addr == r.addr && l.port < r.port );
    }
};

std::map<IpPort, u_int16_t, IpPortCompare> ip_port_map;
std::map<u_int16_t, IpPort> port_ip_map;
std::set<u_int16_t> available_ports;

struct Packet
{
    unsigned int id;
    unsigned char* pktData;
    int len;
};

std::list<Packet> packets;

int PrintPkt( unsigned int id, struct iphdr* iphdr, struct tcphdr* tcphdr )
{
    char buf[80];
    // 1   0.000000    10.3.1.49 -> 137.189.88.150 TCP 74 10000→11000 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=890354428 TSecr=0 WS=128
    printf( "%u ", id );
    printf( "%s:%d -> ", ip_ip2str( iphdr->saddr, buf, sizeof( buf ) ), ntohs( tcphdr->source ) );
    printf( "%s:%d ",    ip_ip2str( iphdr->daddr, buf, sizeof( buf ) ), ntohs( tcphdr->dest ) );
    printf( "[" );
    unsigned count = 0;
    if ( 1 == tcphdr->urg )
    {
        printf( "URG" );
        ++count;
    }
    if ( 1 == tcphdr->ack )
    {
        if ( count > 0 )
        {
            printf( ", " );
        }
        printf( "ACK" );
        ++count;
    }
    if ( 1 == tcphdr->psh )
    {
        if ( count > 0 )
        {
            printf( ", " );
        }
        printf( "PSH" );
        ++count;
    }
    if ( 1 == tcphdr->rst )
    {
        if ( count > 0 )
        {
            printf( ", " );
        }
        printf( "RST" );
        ++count;
    }
    if ( 1 == tcphdr->syn )
    {
        if ( count > 0 )
        {
            printf( ", " );
        }
        printf( "SYN" );
        ++count;
    }
    if ( 1 == tcphdr->fin )
    {
        if ( count > 0 )
        {
            printf( ", " );
        }
        printf( "FIN" );
        ++count;
    }
    printf( "]" );
    printf( "\n" );
    return 0;
}

/*
 * Callback function installed to netfilter queue
 */
static int Callback( nfq_q_handle* myQueue, struct nfgenmsg* msg,
                     nfq_data* pkt, void* cbData )
{
    static unsigned int _fin_count = 0;
    char buf[80];
    unsigned int id = 0;
    nfqnl_msg_packet_hdr* header;

    io_debug( "pkt recvd: " );
    if ( ( header = nfq_get_msg_packet_hdr( pkt ) ) )
    {
        id = ntohl( header->packet_id );
        io_debug( "  id: %u\n", id );
        io_debug( "  hw_protocol: %u\n", ntohs( header->hw_protocol ) );
        io_debug( "  hook: %u\n", header->hook );
    }

    // print the timestamp (PC: seems the timestamp is not always set)
    struct timeval tv;
    if ( !nfq_get_timestamp( pkt, &tv ) )
    {
        io_debug( "  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec );
    }
    else
    {
        io_debug( "  timestamp: nil\n" );
    }

    // Print the payload; in copy meta mode, only headers will be
    // included; in copy packet mode, whole packet will be returned.
    io_debug( " payload: " );
    unsigned char* pktData;
    int len = nfq_get_payload( pkt, ( unsigned char** )&pktData );
    if ( len > 0 )
    {
        for ( int i = 0; i < len; ++i )
        {
            io_debug( "%02x ", pktData[i] );
        }
    }
    io_debug( "\n" );

    struct iphdr* iph = ( struct iphdr* ) pktData;
    io_debug( "source      ip : %s\n", ip_ip2str( iph->saddr, buf, sizeof( buf ) ) );
    io_debug( "destination ip : %s\n", ip_ip2str( iph->daddr, buf, sizeof( buf ) ) );

    // add a newline at the end
    io_debug( "\n" );

    if ( iph->protocol != IPPROTO_TCP )
    {
        // Others, can be ignored
        return nfq_set_verdict( myQueue, id, NF_DROP, len, pktData );
    }
    // TCP packets

    struct tcphdr* tcph = ( struct tcphdr* )( ( ( char* ) iph ) + ( iph->ihl << 2 ) );

    PrintPkt( id, iph, tcph );

//    PrintIpHeader( iph, NULL, 0, stdout );
//    PrintTcp( tcph, stdout );
//    fprintf( stdout, "----------------------------------------\n" );

    u_int16_t port = 0;

    if ( ( ntohl( iph->saddr ) & local_mask ) == ( ntohl( localNetAddr.s_addr ) & local_mask ) )
    {
        // outbound
        // (a) The NAT program searches if the source IP-port pair of the packet has already been stored in the translation table.
        // (b) If not, then the NAT program creates a new entry in the translation table if and only if the outbound packet is a SYN packet.
        //     The entry should contain:
        //     - the source IP-port pair;
        //     - the newly assigned port number (between 10000 and 12000)
        // (c) If the packet is not a SYN packet and the NAT program cannot find any matched entries in
        //     the translation table, the program should drop the packet.
        // (d) If the packet is not a SYN packet but the program can find a matched entry, the program will
        //     use the previously assigned port number.
        // (e) Finally, the NAT program translates the source IP address and the source port number of the
        //     packet, modifies the IP and TCP headers of the packet accordingly, and forwards it.

        IpPort ip_port;
        ip_port.addr = iph->saddr;
        ip_port.port = tcph->source; /* source port */

        std::map<IpPort, u_int16_t>::iterator ite = ip_port_map.find( ip_port );

        if ( ip_port_map.end() == ite && 1 == tcph->syn )
        {
            // (b)
            io_debug( "outbound (b)\n" );
            if ( available_ports.empty() )
            {
                printf( "error: No available ports. Failed to create new nat entry\n" );
                exit( 1 );
            }
            else
            {
                port = *( available_ports.begin() );
                available_ports.erase( available_ports.begin() );

                printf( "A new nat entry is added. ip:port %s:%d -> port %d\n", ip_ip2str( ip_port.addr, buf, sizeof( buf ) ), ip_port.port, port );

                ip_port_map.insert( std::make_pair( ip_port, port ) );
                port_ip_map.insert( std::make_pair( port, ip_port ) );
            }
        }
        else if ( ip_port_map.end() == ite && 0 == tcph->syn )
        {
            // (c)
            io_debug( "outbound (c)\n" );
        }
        else if ( ip_port_map.end() != ite && 0 == tcph->syn )
        {
            // (d)
            io_debug( "outbound (d)\n" );
            port = ite->second;
        }
        else if ( ip_port_map.end() != ite && 1 == tcph->syn )
        {
            // ???
            io_debug( "outbound ???\n" );
        }

        // need to handle RST/FIN to get port back

        if ( 0 == port )
        {
            // drop
            io_debug( "drop\n" );
            return nfq_set_verdict( myQueue, id, NF_DROP, len, pktData );
        }
        else
        {
            io_debug( "Original source ip:port : %s:%d -> ",
                      ip_ip2str( iph->saddr, buf, sizeof( buf ) ), ntohs( tcph->source ) );
            io_debug( "Translated source ip:port : %s:%d\n",
                      ip_ip2str( publicNetAddr.s_addr, buf, sizeof( buf ) ), port );

            iph->saddr   = publicNetAddr.s_addr;
            tcph->source = htons( port );
            iph->check   = ip_checksum( pktData );
            tcph->check  = tcp_checksum( pktData );
        }
    }
    else
    {
        // inbound traffic
        // (a) The NAT program searches if the destination port of the inbound packet matches any one of
        //     the entries in the TCP translation table.
        // (b) If yes, the NAT program translates its destination IP address and port number, modifies the
        //     IP and TCP headers of the packet accordingly, and sends it to the target VM.
        // (c) If not, the NAT program should drop the packet.

        // need to handle RST/FIN to get port back

        std::map<u_int16_t, IpPort>::iterator ite = port_ip_map.find( htons( tcph->dest ) );

        if ( port_ip_map.end() != ite  )
        {
            // (b)
            io_debug( "inbound (b)\n" );
            {
                struct in_addr old_addr;
                old_addr.s_addr = iph->daddr;
                struct in_addr new_addr;
                new_addr.s_addr = ite->second.addr;
                io_debug( "Map destination ip:port : %s:%d -> %s:%d\n",
                          inet_ntoa( old_addr ), ntohs( tcph->dest ),
                          inet_ntoa( new_addr ), ntohs( ite->second.port ) );
            }
            port = ite->second.port;
            iph->daddr  = ite->second.addr;
            tcph->dest  = ite->second.port;
            iph->check  = ip_checksum( pktData );
            tcph->check = tcp_checksum( pktData );
        }
        else
        {
            // (c)
            // drop
            io_debug( "inbound (c) drop\n" );
            return nfq_set_verdict( myQueue, id, NF_DROP, len, pktData );
        }
    }

    if ( 1 == tcph->fin )
    {
        _fin_count++;
        if ( _fin_count > 2 )
        {
            printf( "error: fin count %u > 2\n", _fin_count );
            exit( 1 );
        }
        if ( 1 == _fin_count )
        {
            io_debug( "FIN_WAIT_1" );
        }
        else if ( 2 == _fin_count )
        {
            io_debug( "FIN_WAIT_2" );
        }
    }
    else if ( 2 == _fin_count && 1 == tcph->ack )
    {
        // last ack, closed
        io_debug( "LAST_ACK, take port %d back\n", port );
        available_ports.insert( port );
        _fin_count = 0;
    }
    else if ( 1 == tcph->rst )
    {
        io_debug( "RST, take port %d back\n", port );
        available_ports.insert( port );
        _fin_count = 0;
    }


    Packet p;
    p.id = id;
    p.len = len;
    p.pktData = ( unsigned char* )malloc( sizeof( unsigned char* )*len );
    memcpy( p.pktData, pktData, len );
    packets.push_back( p );

//    return nfq_set_verdict( myQueue, id, NF_ACCEPT, len, pktData );
    return 0;

    // end Callback
}

bool _comsume( size_t& token_bucket, size_t i )
{
    if ( token_bucket < i )
    {
        return false;
    }

    token_bucket -= i;

    return true;
}

/*
 * Worker thread performing receiving and outputing messages
 */
void* pthread_prog( void* fd )
{
    struct nfq_q_handle* myQueue = ( nfq_q_handle* ) fd;

    struct timespec req, rem;
    req.tv_sec = 0;
    req.tv_nsec = ( 1.0 / ( double ) fill_rate ) * 1000000;
    size_t mytokenbucket = 0;
    while ( 1 )
    {
        if ( nanosleep( &req, &rem ) < 0 )
        {
            printf( "error: nanosleep() system call failed!\n" );
            exit( 1 );
        }
        ++mytokenbucket;
        while ( !packets.empty() && _comsume( mytokenbucket, 1 ) )
        {
            // send packet
            io_debug( "bucket thread\n" );
            nfq_data* pkt = ( nfq_data* )packets.front().pktData;

            char buf[80];
            unsigned int id = packets.front().id;
            io_debug( "  id: %u\n", id );

            // Print the payload; in copy meta mode, only headers will be
            // included; in copy packet mode, whole packet will be returned.
            io_debug( " payload: " );
            unsigned char* pktData = packets.front().pktData;
            int len = packets.front().len;
            if ( len > 0 )
            {
                for ( int i = 0; i < len; ++i )
                {
                    io_debug( "%02x ", pktData[i] );
                }
            }
            io_debug( "\n" );

            struct iphdr* iph = ( struct iphdr* ) pktData;
            io_debug( "source      ip : %s\n", ip_ip2str( iph->saddr, buf, sizeof( buf ) ) );
            io_debug( "destination ip : %s\n", ip_ip2str( iph->daddr, buf, sizeof( buf ) ) );

            // add a newline at the end
            io_debug( "\n" );
            if ( nfq_set_verdict( myQueue, id, NF_ACCEPT, len, pktData ) < 0 )
            {
                printf( "error: nfq_set_Verdict() failed!\n" );
                exit( 1 );
            }

            free( pkt );
            packets.pop_front();
        }
    }
}

/*
 * Main program
 */
int main( int argc, char** argv )
{
    if ( argc != 6 )
    {
        fprintf( stderr, "Usage: %s <IP> <LAN> <MASK> <bucket size> <fill rate>\n", argv[0] );
        exit( -1 );
    }
    // Public IP  : 10.3.1.49
    // Internal IP: 10.0.49.[0-255]
    // Subnet mask: 24
    // Bucket size: size of token bucket, e.g., 2048
    // Fill rate  : rate of generating tokens, e.g., 1024

    mask_int = atoi( argv[3] );
    local_mask = 0xffffffff << ( 32 - mask_int );

    publicNetAddr.s_addr = inet_addr( argv[1] );
    localNetAddr.s_addr = inet_addr( argv[2] );

    bucket_size = atoi( argv[4] );
    fill_rate   = atoi( argv[5] );

    ip_port_map.clear();
    port_ip_map.clear();

    std::vector<u_int16_t> ports( 12000 - 10000 + 1 );
    std::iota( ports.begin(), ports.end(), 10000 );
    available_ports = std::set<u_int16_t>( ports.begin(), ports.end() );
    packets.clear();

    struct nfq_handle* nfqHandle;

    struct nfq_q_handle* myQueue;
    struct nfnl_handle* netlinkHandle;

    int fd, res;
    char buf[4096];

    printf( "Start nat\n" );

    // Get a queue connection handle from the module
    if ( !( nfqHandle = nfq_open() ) )
    {
        fprintf( stderr, "Error in nfq_open()\n" );
        exit( -1 );
    }

    // Unbind the handler from processing any IP packets
    // (seems to be a must)
    if ( nfq_unbind_pf( nfqHandle, AF_INET ) < 0 )
    {
        fprintf( stderr, "Error in nfq_unbind_pf()\n" );
        exit( 1 );
    }

    // Bind this handler to process IP packets...
    if ( nfq_bind_pf( nfqHandle, AF_INET ) < 0 )
    {
        fprintf( stderr, "Error in nfq_bind_pf()\n" );
        exit( 1 );
    }

    // Install a callback on queue 0
    if ( !( myQueue = nfq_create_queue( nfqHandle,  0, &Callback, NULL ) ) )
    {
        fprintf( stderr, "Error in nfq_create_queue()\n" );
        exit( 1 );
    }

    // Turn on packet copy mode
    if ( nfq_set_mode( myQueue, NFQNL_COPY_PACKET, 0xffff ) < 0 )
    {
        fprintf( stderr, "Could not set packet copy mode\n" );
        exit( 1 );
    }

    pthread_t worker;
    pthread_create( &worker, NULL, pthread_prog, myQueue );

    netlinkHandle = nfq_nfnlh( nfqHandle );
    fd = nfnl_fd( netlinkHandle );

    while ( ( res = recv( fd, buf, sizeof( buf ), 0 ) ) && res >= 0 )
    {
        // I am not totally sure why a callback mechanism is used
        // rather than just handling it directly here, but that
        // seems to be the convention...
        nfq_handle_packet( nfqHandle, buf, res );
        // end while receiving traffic
    }

    nfq_destroy_queue( myQueue );

    nfq_close( nfqHandle );

    return 0;

    // end main
}


