#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>

#define ETHER_TYPE_IPV4 0X800
#define ETHER_TYPE_ARP 0X806

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line 
	init(argc - 2, argv + 2);


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

			
		}

		/*Checks if EtherType is ARP*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {

		}

	}
}

