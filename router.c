#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHER_TYPE_IPV4 0X800
#define ETHER_TYPE_ARP 0X806





int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line 
	init(argc - 2, argv + 2);

	/*Reading rtables*/
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtable_size = read_rtable(argv[1], rtable);

	/**/
	struct arp_table_entry *arp_table = malloc(sizeof(arp_table)*100000);
	int arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	/**/

	printf("%d", rtable[123].prefix);


	while (1) {

		int interface;
		size_t len;

		printf("************\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/*Gets the interfaces' MAC address*/
		// uint8_t *interface_mac = malloc(6 * sizeof(uint8_t));
		// get_interface_mac(interface, interface_mac);

		// /*Verifies if the packet is valid or not'*/
		// uint8_t packet_not_valid = 0;
		// for (int i = 0; i < 6; i++) {
		// 	/*For MAC interface*/
		// 	if (ntohs(eth_hdr->ether_dhost[i]) != interface_mac[i]) {
		// 		packet_not_valid = 1;
		// 		break;
		// 	}
		// 	/*For broadcast*/
		// 	if (ntohs(eth_hdr->ether_dhost[i]) != 0xff) {
		// 		packet_not_valid = 1;
		// 		break;
		// 	}
		// }
		// /*If the packet is not valid, it drops it (continues receiving packets)*/
		// if (packet_not_valid) {
		// 	// continue;
		// }
		


		/*Checks if EtherType is IPv4*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IPV4) {
			printf("Ether type: IPV4\n");
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/*Checks if the protocol is ICMP*/
			printf("Protocol: %d ", ip_hdr->protocol);
			if (ip_hdr->protocol == 1) {
				printf("ICMP\n");
				uint32_t interface_ip = inet_addr(get_interface_ip(interface));
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));

				printf("interface_ip: %d.%d.%d.%d   dest_addr: %d.%d.%d.%d\n", (ntohl(interface_ip) >> 24) & 255, (ntohl(interface_ip) >> 16) & 255, (ntohl(interface_ip) >> 8) & 255, (ntohl(interface_ip) >> 0) & 255
				,(ntohl(ip_hdr->daddr) >> 24) & 255 ,(ntohl(ip_hdr->daddr) >> 16) & 255, (ntohl(ip_hdr->daddr) >> 8) & 255, (ntohl(ip_hdr->daddr) >> 0) & 255);
				printf("icmp type: %u\n", icmp_hdr->type);
				/*Checks if it's an echo reply for us*/
				if (interface_ip == ip_hdr->daddr && icmp_hdr->type == 8) {
					/*ICMP Echo Reply*/

				/*Swap in ether header source mac with destination mac*/
				uint8_t tmp[6];
				memcpy(tmp, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_dhost, tmp, sizeof(uint8_t) * 6);

				printf("iphdr original len: %u\n", ip_hdr->tot_len);
				/*Modify the ip header accordingly*/
				ip_hdr->protocol = 1; //icmp protocol
				// ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->ttl = 64;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = inet_addr(get_interface_ip(interface));
				ip_hdr->check = 0;


				/*ICMP header*/
				icmp_hdr->code = 0;
				icmp_hdr->type = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, (ip_hdr->tot_len/256) - sizeof(struct iphdr)));


				/*Sending packet*/
				send_to_link(interface, buf, sizeof(struct ether_header) + (ip_hdr->tot_len/256));

				printf("Sending packet...\n");
				printf("//////////////////\n");
				printf("MAC src: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5] );
				printf("MAC dst: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5] );
				printf("Ether type: %u\n", eth_hdr->ether_type);
				printf("Iphdr checksum: %u\n", ip_hdr->check);
				printf("Iphdr protocol: %u\n", ip_hdr->protocol);
				printf("src ip: %d.%d.%d.%d   dest ip: %d.%d.%d.%d\n", (ntohl(ip_hdr->saddr) >> 24) & 255, (ntohl(ip_hdr->saddr) >> 16) & 255, (ntohl(ip_hdr->saddr) >> 8) & 255, (ntohl(ip_hdr->saddr) >> 0) & 255
				,(ntohl(ip_hdr->daddr) >> 24) & 255 ,(ntohl(ip_hdr->daddr) >> 16) & 255, (ntohl(ip_hdr->daddr) >> 8) & 255, (ntohl(ip_hdr->daddr) >> 0) & 255);
				printf("Iphdr tot len: %u\n", ip_hdr->tot_len);
				printf("ICMP code: %u   ICMP type: %u\n", icmp_hdr->code, icmp_hdr->type);
				printf("ICMP checksum: %u\n", icmp_hdr->checksum);
				printf("//////////////////\n");
				continue;
				}
			}

			/*Checks checksum, if it doesn't check it drops the packet*/
			if (0 != checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len))) {
				printf("Wrong checksum. Dropping...\n");
				continue;
			}

			/*TTL
			If the ttl is 0 or 1 (lower or equal 1) then the packet is dropped
			If not, the ttl is decremented*/
			if (ntohs(ip_hdr->ttl) <= 1) {
				
				/*ICMP Time excedeed*/

				/*Swap in ether header source mac with destination mac*/
				uint8_t tmp[6];
				memcpy(tmp, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_dhost, tmp, sizeof(uint8_t) * 6);


				/*Modify the ip header accordingly*/
				ip_hdr->protocol = htons(1); //icmp protocol
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));  //new total length iphdr + icmphdr
				ip_hdr->ttl = htons(64);
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = htonl(inet_addr(get_interface_ip(interface)));
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->check = 0;


				/*ICMP header*/
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(ip_hdr));
				icmp_hdr->code = htons(0);
				icmp_hdr->type = htons(11);
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));


				/*Sending packet*/
				send_to_link(interface, (char *)eth_hdr, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

				printf("Time exceeded. Dropping...\n");
				continue;
			} else {
				ip_hdr->ttl = htons(ntohs(ip_hdr->ttl) - 1);
			}


			printf("Searching the ARP table...\n");
			/*Searching the static ARP table*/
			uint8_t destination_not_found = 1;
			uint8_t destination_mac[6];
			for(int i = 0; i < arp_table_size; i++) {
				if (ntohl(ip_hdr->daddr) == arp_table[i].ip) {
					memcpy(destination_mac, arp_table[i].mac, sizeof(uint8_t) * 6);
					destination_not_found = 0;
					break;
				}
			}
			/**/

			// TODO: Search rtable

			if (destination_not_found) {

				/* ICMP Destination Unrechable */

				/*Swap in ether header source mac with destination mac*/
				uint8_t tmp[6];
				memcpy(tmp, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_dhost, tmp, sizeof(uint8_t) * 6);


				/*Modify the ip header accordingly*/
				ip_hdr->protocol = htons(1); //icmp protocol
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));  //new total length iphdr + icmphdr
				ip_hdr->ttl = htons(64);
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = htonl(inet_addr(get_interface_ip(interface)));
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->check = 0;


				/*ICMP header*/
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(ip_hdr));
				icmp_hdr->code = htons(0);
				icmp_hdr->type = htons(3);
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));


				/*Sending packet*/
				send_to_link(interface, (char *)eth_hdr, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				continue;
			}

			/*Recalculating checksum due to TTL change*/
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len)));
		}

		/*Checks if EtherType is ARP*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {

		}

	}
}

