/*
 *
 *
 */

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/igmp.h>
#include <netinet/ip6.h>
#include <linux/dccp.h>
#define ui unsigned int
#define LF capture_packet
#define logfile second_file
FILE *capture_packet;
FILE *second_file;
struct header{
	uint16_t tid;
	uint16_t flags;
	uint16_t nqueries;
	uint16_t nanswers;
	uint16_t nauth;
	uint16_t nother;
};
inline void parse_http(char *buf)
{	puts(buf);
	int i=0;
	for(i=0;i<(int)strlen(buf);i++)
	{
		if(i!=0&&i%16==0)
		{
			for(int j=i-16;j<i;j++)
			{
				if(buf[i]>=32&&buf[i]<=128)
				{
					printf("%c ",(unsigned char*)buf[i]);
				}
				else
				{
					printf(".");
				}
			}
			printf("\n");
		}
	}
	exit(0);
	/*for(i=0;i<(int)strlen(buf);i++)
	{
		printf("%d ",buf[i]);
	}
	printf("\n");
	if((buf[0]/2)=='G'||(buf[0]/2)=='P'||(buf[0]=='D'))
	{
		puts("buffalo");
		//fputs(buf,LF);
	}
	else
	{
		if((buf[0]/2)=='H'&&(buf[1]/2)=='T')
		{
			puts("cow");
			//fputs(buf,LF);
		}
		else if((buf[0]/2)=='H'&&(buf[1]/2)=='E')
		{
			puts("doggy");
			//fputs(buf,LF);
		}
	}
	puts("hello");
	exit(0);
	fprintf(LF,"Request Message\n");
	fprintf(LF,"Method: ");
	while(buf[i]!=' '){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	fprintf(LF,"URL field: ");
	while(buf[i]==' ')i++;
	while(buf[i]!=' '){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	fprintf(LF,"HTTP Version: ");
	while(buf[i]==' ')i++;
	while(buf[i]!=' '||buf[i]!='\r'||buf[i]!='\n'){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");

	while(buf[i]!='\n')i++;
	i++;
	while(buf[i]!='\n'){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	i++;

	while(buf[i]!='\n'){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	i++;

	while(buf[i]!='\n'){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	i++;

	while(buf[i]!='\n'){
		fprintf(LF,"%c",buf[i]);
		i++;
	}
	fprintf(LF,"\n");
	i++;
	fprintf(LF,"Response Message\n");*/
}
inline void parse_dns(char *buf)
{
	/*puts("shdbvhsbvhrbef");
	//fputs(buf,LF);
	struct header *dnsh =(struct header*)buf;
	fprintf(LF,"DNS Packet\n");
	fprintf(LF,"Identifier: %u\n",dnsh->tid);
	fprintf(LF,"Flags: %d\n",ntohs(dnsh->flags));
	//
	/*fprintf(LF,"Query/Response flag(QR) %d\n",);
	fprintf(LF,"Operation code %d\n",);
	fprintf(LF,"Authoritatice answer (AA): %d\n",);
	fprintf(LF,"Truncation Flag:%d\n",);
	fprintf(LF,"Recursion Desired: %d\n",);
	fprintf(LF,"Recursion Available: %d\n",);
	fprintf(LF,"RCode: %d\n",);
	//
	////http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
	//
	fprintf(LF,"Question count: %u\n",dnsh->nqueries);
	fprintf(LF,"Answer record count: %u\n",dnsh->nanswers);
	fprintf(LF,"Name server( Authority record) count: %u\n",dnsh->nauth);
	fprintf(LF,"Additional record count: %u\n",dnsh->nother);*/
}
inline void parse_dhcp()
{

}
inline void parse_tcp(char *buf)
{
	struct tcphdr *tcph=(struct tcphdr *)buf;
	fprintf(LF,"TCP Packet\n");
	fprintf(LF,"Source Port: %u\n",ntohs(tcph->source));
	fprintf(LF,"Destination Port: %u\n",ntohs(tcph->dest));
	fprintf(LF,"Sequence number: %u\n",ntohs(tcph->seq));
	fprintf(LF,"Acknowledgment number: %u\n",ntohs(tcph->ack_seq));
	fprintf(LF,"Header Length %u\n",(ui)tcph->doff);
	fprintf(LF,"\nFlags:\n");
	fprintf(LF,"Reserved: %u\n",(ui)tcph->res1);
	fprintf(LF,"Urgent: %u\n",(ui)tcph->urg);
	fprintf(LF,"Acknowledgement: %u\n",(ui)tcph->ack);
	fprintf(LF,"Push: %u\n",(ui)tcph->psh);
	fprintf(LF,"Reset: %u\n",(ui)tcph->rst);
	fprintf(LF,"Syn: %u\n",(ui)tcph->syn);
	fprintf(LF,"\nTCP Flags:\n");
	fprintf(LF,"Window size value: %u\n",ntohs(tcph->window));
	fprintf(LF,"Checksum: %u\n",ntohs(tcph->check));
	fprintf(LF,"Urgent pointer: %u\n",tcph->urg_ptr);
	if(ntohs(tcph->source)==80)
	{
		parse_http(buf+(ui)(tcph->doff)*4);
	}
	else if(ntohs(tcph->source)==53)
	{
		parse_dns(buf+(ui)(tcph->doff)*4);
	}
}
inline void parse_udp(char *buf)
{
	struct udphdr *udph=(struct udphdr *)buf;
	fprintf(LF,"UDP Packet\n");
	fprintf(LF,"Source Port: %u\n",ntohs(udph->source));
	fprintf(LF,"Destination Port: %u\n",ntohs(udph->dest));
	fprintf(LF,"Length: %u\n",ntohs(udph->len));
	fprintf(LF,"Checksum: %u\n",ntohs(udph->check));
	if(ntohs(udph->source)==80)
	{
		parse_http(buf+ntohs(udph->len));
	}
	else if(ntohs(udph->source)==53)
	{
		parse_dns(buf+ntohs(udph->len));
	}
}
inline void parse_dccp(char *buf)
{
	struct dccp_hdr *dccph=(struct dccp_hdr*)buf;

	//http://lxr.free-electrons.com/source/include/uapi/linux/dccp.h
	//https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol
	fprintf(LF,"\nDCCP Packet\n");
	fprintf(LF,"Source Port: %u\n",ntohs(dccph->dccph_sport));
	fprintf(LF,"Destination Port: %u\n",ntohs(dccph->dccph_dport));
	fprintf(LF,"Header Length: %u\n",(ui)dccph->dccph_doff);
	fprintf(LF,"CCVal: %u\n",dccph->dccph_ccval);
	fprintf(LF,"CsCov: %u\n",dccph->dccph_cscov);
	fprintf(LF,"Checksum: %u\n",ntohs(dccph->dccph_checksum));
	fprintf(LF,"Reserved: %u\n",dccph->dccph_reserved);
	fprintf(LF,"Type: %u\n",dccph->dccph_type);
	fprintf(LF,"X: %u\n",dccph->dccph_x);
	fprintf(LF,"Sequence Number (high): %u\n",dccph->dccph_seq2);
	fprintf(LF,"Sequence Number (low bits): %u\n",ntohs(dccph->dccph_seq));
	if(ntohs(dccph->dccph_sport)==80)
	{
		parse_http(buf+dccph->dccph_doff);
	}
	else if(ntohs(dccph->dccph_sport)==53)
	{
		parse_dns(buf+dccph->dccph_doff);
	}
}
inline void parse_icmp(char *buf)
{
	struct icmphdr *icmph=(struct icmphdr *)buf;
	fprintf(LF,"\nICMP Packet\n");
	fprintf(LF,"Type %u ",ntohs(icmph->type));
	switch(icmph->type)
	{
		case 0:
			fprintf(LF,"Echo Reply\n");
			break;
		case 3:
			fprintf(LF,"Destination Unreachable\n");
			break;
		case 5:
			fprintf(LF,"Redirect\n");
			break;
		case 8:
			fprintf(LF,"Echo\n");
			break;
		case 9:
			fprintf(LF,"Router Advertisement\n");
			break;
		case 10:
			fprintf(LF,"Router Solicitation\n");
			break;
		case 11:
			fprintf(LF,"Timer Exceeded\n");
			break;
		case 12:
			fprintf(LF,"Parameter Problem\n");
			break;
		case 13:
			fprintf(LF,"Timestamp\n");
			break;
		case 14:
			fprintf(LF,"Timestamp Reply\n");
			break;
		default:
			break;
	}
	fprintf(LF,"Code: %d\n",(ui) icmph->code);
	fprintf(LF,"Checksum: %d\n",(ui) icmph->checksum);
	// after this print data.
}
/*inline void parse_igmp(char *buf,int version)
{
	struct sockaddr_in src;
	struct igmpv3 *igmphh=(struct igmpv3 *)buf;
	struct igmp *igmph=(struct igmp *)buf;
	switch(version)
	{
		case 2:
			fprintf(LF,"Version & type of IGMP message: %d\n",igmph->igmp_type);
			fprintf(LF,"Subtype for Routing messages:  %d\n",igmph->igmp_code);
			fprintf(LF,"Checksum %d\n",igmph->igmp_cksum);
			src.sin_addr.s_addr=igmph->igmp_group.s_addr;
			fprintf(LF,"Group Address: %s\n",inet_ntoa(src.sin_addr));
			break;
		case 3:
			fprintf(LF,"Type of IGMP message: %d\n",igmphh->igmp_type);
			fprintf(LF,"Max Resp Code:  %d\n",igmphh->igmp_code);
			fprintf(LF,"Checksum: %d\n",ntohs(igmphh->igmp_cksum));
			src.sin_addr.s_addr=igmph->igmp_group.s_addr;
			fprintf(LF,"Group Address: %s\n",inet_ntoa(src.sin_addr));
			fprintf(LF,"Reserved/Suppress/Robustness:%d\n",igmphh->igmp_misc);
			fprintf(LF,"Query Interval:%d\n",igmphh->igmp_qqi);
			fprintf(LF,"Number of sources:%d\n",igmphh->igmp_numsrc);
			int i;
			for(i=0;i<(int)igmphh->igmp_numsrc;i++)
			{
				src.sin_addr.s_addr=buf[i*4+12];
				fprintf(LF,"Source %d ip address: %s\n",i+1,inet_ntoa(src.sin_addr));
			}
			break;
		default:
			break;
	}
}*/
inline void parse_ipv4(char *buf)
{
	struct sockaddr_in src,dest;
	struct iphdr *iph_hdr=(struct iphdr *)buf;
	int ip_hdr_len=iph_hdr->ihl*4;
	fprintf(LF,"Version: %d\n",iph_hdr->version);
	fprintf(LF,"IHL: %d\n",iph_hdr->ihl);
	fprintf(LF,"DSCP: %d\n",iph_hdr->tos&252);
	fprintf(LF,"ECN: %d\n",iph_hdr->tos&3);
	fprintf(LF,"Total Length: %d\n",ntohs(iph_hdr->tot_len));
	fprintf(LF,"Identification: %d\n",ntohs(iph_hdr->id));
	fprintf(LF,"FLAGS: %d\n",ntohs(iph_hdr->frag_off)&(((1<<16)-1)-((1<<13)-1)));
	fprintf(LF,"FRAGMENT OFFSET: %d\n",ntohs(iph_hdr->frag_off)&((1<<13)-1));
	fprintf(LF,"TTL: %d\n",iph_hdr->ttl);
	fprintf(LF,"PROTOCOL: %d\n",iph_hdr->protocol);
	fprintf(LF,"CHECKSUM: %d\n",ntohs(iph_hdr->check));
	src.sin_addr.s_addr=iph_hdr->saddr;
	dest.sin_addr.s_addr=iph_hdr->daddr;
	fprintf(LF,"Source ip address: %s\n",inet_ntoa(src.sin_addr));
	fprintf(LF,"Destination ip address: %s\n",inet_ntoa(dest.sin_addr));
	if(iph_hdr->ihl>5)
	{
		fprintf(LF,"Options Field Present.\n");
	}
	if(iph_hdr->protocol==6)
	{
		parse_tcp(buf+ip_hdr_len);
	}
	else if(iph_hdr->protocol==17)
	{
		parse_udp(buf+ip_hdr_len);
	}
	else if(iph_hdr->protocol==1)
	{
		parse_icmp(buf+ip_hdr_len);
	}
}
inline void parse_ipv6(char *buf)
{
	struct sockaddr_in6 src,dest;
	struct ip6_hdr *iph_hdr=(struct ip6_hdr *)buf;
	fprintf(LF,"Version: %d\n",iph_hdr->ip6_vfc&(((1<<8)-1)-((1<<4)-1)));
	fprintf(LF,"Class: %d\n",iph_hdr->ip6_vfc&((1<<4)-1));
	fprintf(LF,"Flow Label: %d\n",ntohs(iph_hdr->ip6_flow));
	fprintf(LF,"Payload Length: %d\n",ntohs(iph_hdr->ip6_plen));
	fprintf(LF,"Next Header: %d\n",iph_hdr->ip6_nxt);
	fprintf(LF,"Hop Limit: %d\n",ntohs(iph_hdr->ip6_hlim));
	int i;
	for(i=0;i<16;i++)
	{
		src.sin6_addr.s6_addr[i]=iph_hdr->ip6_src.s6_addr[i];
		dest.sin6_addr.s6_addr[i]=iph_hdr->ip6_dst.s6_addr[i];
	}
	for(i=0;i<8;i++)
	{
		src.sin6_addr.s6_addr16[i]=iph_hdr->ip6_src.s6_addr16[i];
		dest.sin6_addr.s6_addr16[i]=iph_hdr->ip6_dst.s6_addr16[i];
	}
	for(i=0;i<4;i++)
	{
		src.sin6_addr.s6_addr32[i]=iph_hdr->ip6_src.s6_addr32[i];
		dest.sin6_addr.s6_addr32[i]=iph_hdr->ip6_dst.s6_addr32[i];
	}
	char str[1000];
	inet_ntop(AF_INET6,&(src.sin6_addr), str, INET6_ADDRSTRLEN);
	fprintf(LF,"Source ip address: %s\n",str);
	fprintf(LF,"Destination ip address: %s\n",str);
	int upp_layer=-1,add_len=0;
	add_len=sizeof(struct ip6_hdr);
	upp_layer=iph_hdr->ip6_nxt;
	while(1)
	{
		if(upp_layer==0||upp_layer==43||upp_layer==44||upp_layer==50||upp_layer==51||upp_layer==60||upp_layer==135||upp_layer==139||upp_layer==140||upp_layer==253||upp_layer==254)
		{
			upp_layer=(int)buf[add_len];
			add_len+=(int)buf[add_len+1];
		}
		else
		{
			break;
		}
	}
	if(upp_layer==6)
	{
		parse_tcp(buf+add_len);
	}
	else if(upp_layer==17)
	{
		parse_udp(buf+add_len);
	}
	else if(upp_layer==1)
	{
		parse_icmp(buf+add_len);
	}
}
inline void parse_arp(char *buf)
{
	struct ether_arp *arp_hdr=(struct ether_arp *)buf;
	fprintf(LF,"%d\n",htons(arp_hdr->arp_hrd));
	fprintf(LF,"%d\n",htons(arp_hdr->arp_pro));
	fprintf(LF,"%d\n",arp_hdr->arp_hln);
	fprintf(LF,"%d\n",arp_hdr->arp_pln);
	fprintf(LF,"%d\n",htons(arp_hdr->arp_op));
	fprintf(LF,"SOURCE MAC ADDRESS:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",arp_hdr->arp_sha[0],arp_hdr->arp_sha[1],arp_hdr->arp_sha[2],arp_hdr->arp_sha[3],arp_hdr->arp_sha[4],arp_hdr->arp_sha[5]);
	fprintf(LF,"Source ip address:%d.%d.%d.%d\n",arp_hdr->arp_spa[0],arp_hdr->arp_spa[1],arp_hdr->arp_spa[2],arp_hdr->arp_spa[3]);
	fprintf(LF,"DESTINATION MAC ADDRESS:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",arp_hdr->arp_tha[0],arp_hdr->arp_tha[1],arp_hdr->arp_tha[2],arp_hdr->arp_tha[3],arp_hdr->arp_tha[4],arp_hdr->arp_tha[5]);
	fprintf(LF,"Destination ip address:%d.%d.%d.%d\n",arp_hdr->arp_tpa[0],arp_hdr->arp_tpa[1],arp_hdr->arp_tpa[2],arp_hdr->arp_tpa[3]);
}
inline void parse_eth(char *buf)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)buf;
	int val=eth_hdr->h_proto;
	fprintf(LF,"ETHERTYPE: %d\n",val);
	fprintf(LF,"ETHERNET SOURCE ADDRESS:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth_hdr->h_source[0],eth_hdr->h_source[1],eth_hdr->h_source[2],eth_hdr->h_source[3],eth_hdr->h_source[4],eth_hdr->h_source[5]);
	fprintf(LF,"ETHERNET DEST ADDRESS:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth_hdr->h_dest[0],eth_hdr->h_dest[1],eth_hdr->h_dest[2],eth_hdr->h_dest[3],eth_hdr->h_dest[4],eth_hdr->h_dest[5]);
	if(val==8)
	{
		parse_ipv4(buf+sizeof(struct ethhdr));
	}
	if(val==56710)
	{
		parse_ipv6(buf+sizeof(struct ethhdr));
	}
	else if(val==1544)
	{
		parse_arp(buf+sizeof(struct ethhdr));
	}
	return;
}
int main()
{
	capture_packet=fopen("CapurePacket4.txt","w+");
	int sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sockfd<0)
	{
		perror("Error Creating Socket:");
		exit(1);
	}
	char buf[2000];
	struct sockaddr saddr;
	int saddr_len=sizeof(saddr);
	while(1)
	{
		int buf_len=recvfrom(sockfd,buf,1000,0,&saddr,(socklen_t*)&saddr_len);
		if(buf_len<0)
		{
			perror("Error reading data:");
			exit(1);
		}
		parse_eth(buf);
	}
}
