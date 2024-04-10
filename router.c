#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHER_TYPE_IPV4 0X800
#define ETHER_TYPE_ARP 0X806


/*Converts ip from ascii to uint32_t*/
uint32_t ascii_to_ip(char *ascii) {
	uint32_t ip = 0 + atoi(ascii);
	for (; ascii[0] != 0; ascii++) {
		if(ascii[0] == '.') {
			ip = ip << 8;
			ip += atoi(ascii + 1);
		}
	}
	return ip;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line 
	init(argc - 2, argv + 2);

	/*Reading rtables*/
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rtable_size = read_rtable(argv[1], rtable);

	/**/
	struct arp_table_entry *arp_table = malloc(sizeof(arp_table)*10);
	int arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	/**/

	printf("%d", rtable[123].prefix);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/*Gets the interfaces' MAC address*/
		uint8_t *interface_mac = malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, interface_mac);

		/*Verifies if the packet is valid or not'*/
		uint8_t packet_not_valid = 0;
		for (int i = 0; i < 6; i++) {
			/*For MAC interface*/
			if (ntohs(eth_hdr->ether_dhost[i]) != interface_mac[i]) {
				packet_not_valid = 1;
				break;
			}
			/*For broadcast*/
			if (ntohs(eth_hdr->ether_dhost[i]) != 0xff) {
				packet_not_valid = 1;
				break;
			}
		}
		/*If the packet is not valid, it drops it (continues receiving packets)*/
		if (packet_not_valid) {
			continue;
		}


		/*Checks if EtherType is IPv4*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IPV4) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/*Checks checksum, if it doesn't check it drops the packet*/
			if (ntohs(ip_hdr->check) != checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len))) {
				continue;
			}

			/*TTL
			If the ttl is 0 or 1 (lower or equal 1) then the packet is dropped
			If not, the ttl is decremented*/
			if (ntohs(ip_hdr->ttl) <= 1) {
				// TODO: ICMP Time exceeded

				/*Swap in ether header source mac with destination mac*/
				uint8_t tmp[6];
				memcpy(tmp, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_dhost, tmp, sizeof(uint8_t) * 6);


				/**/
				ip_hdr->protocol = htons(1); //icmp protocol
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));  //new total length iphdr + icmphdr
				ip_hdr->daddr = ip_hdr->saddr;

				
				char *interface_ip_string = get_interface_ip(interface);  //gets interface ip in string form
				ip_hdr->saddr = hton(ascii_to_ip(interface_ip_string));
				struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + sizeof(ip_hdr));

				continue;
			} else {
				ip_hdr->ttl = htons(ntohs(ip_hdr->ttl) - 1);
			}


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
				// TODO: ICMP Destination Unrechable
				continue;
			}

			/*Recalculating checksum due to TTL change*/
			ip_hdr->check = htons(checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len)));
		}

		/*Checks if EtherType is ARP*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {

		}

	}
}

