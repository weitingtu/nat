#ifndef __PRINT__

#define __PRINT__

#include <netinet/ip.h>
#include <stdio.h>

char* ip_ip2str( u_int32_t ip, char* buf, socklen_t size );
int PrintIpHeader( struct iphdr* iphdr, u_char* option, int optionLen, FILE* fp );
int PrintTcp( struct tcphdr* tcphdr, FILE* fp );

#endif
