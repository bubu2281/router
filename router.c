#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHER_TYPE_IPV4 0X800
#define ETHER_TYPE_ARP 0X806
#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_REPLY 0
#define ICMP_TYPE_TIME_EXCEDEED 11
#define ICMP_TYPE_DEST_UNREACH 3

struct packet {
	char *buf;
	int interface;
	size_t length;
	uint32_t next_hop;
};

int cmp_rtable(const void *a, const void *b) {
	struct route_table_entry *entry1 = (struct route_table_entry *)a;
	struct route_table_entry *entry2 = (struct route_table_entry *)b;
	if ((entry1->prefix) < (entry2->prefix)) {
		return -1;
	} else if ((entry1->prefix) > (entry2->prefix)) {
		return 1;
	} else if ((entry1->mask) <= (entry2->mask)) {
		return -1;
	} else {
		return 1;
	}
}



int binarySearch(struct route_table_entry *rtable, int l, int r, uint32_t x)
{
    if (r >= l) {
        int mid = l + (r - l) / 2;
        // if (rtable[mid].prefix == (x & rtable[mid].mask) )
		if (rtable[mid].prefix == (x & htonl(0xffffff00)) && rtable[mid].mask == htonl(0xffffff00))
            return mid;
        if (rtable[mid].prefix > (x & htonl(0xffffff00)) || rtable[mid].mask > htonl(0xffffff00))
            return binarySearch(rtable, l, mid - 1, x);
        return binarySearch(rtable, mid + 1, r, x);
    }
    return -1;
}

void send_icmp_packet(uint8_t type, char *buf, struct ether_header* eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, int interface) {
	uint8_t interface_mac[6];
	get_interface_mac(interface, interface_mac);


	/*Swap in ether header source mac with destination mac*/
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
	memcpy(eth_hdr->ether_shost, interface_mac, sizeof(uint8_t) * 6);


	/*Modify the ip header accordingly*/
	ip_hdr->protocol = 1; //icmp protocol
	if (type != ICMP_TYPE_REPLY) {
		ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8); // Internet Header + 64 bits of Original Data Datagram 
	}
	ip_hdr->ttl = 64;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->check = 0;


	/*ICMP header*/
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	icmp_hdr->un.gateway = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));


	/*Sending packet*/
	send_to_link(interface, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));

}


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
	// int arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	int arp_table_size = 0;
	/**/

	/*Sorting rtable*/
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp_rtable);

	queue packet_queue;
	packet_queue = queue_create();





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
		uint8_t interface_mac[6];
		get_interface_mac(interface, interface_mac);



		/*Checks if EtherType is IPv4*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IPV4) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));



			uint32_t interface_ip = inet_addr(get_interface_ip(interface));
			struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));

			/*Checks if it's an echo reply for us*/
			if (interface_ip == ip_hdr->daddr && icmp_hdr->type == ICMP_TYPE_REQUEST) { 

				/*ICMP Echo Reply*/
				send_icmp_packet(ICMP_TYPE_REPLY, buf, eth_hdr, ip_hdr, icmp_hdr, interface);
				continue;
			}

			/*Checks checksum, if it doesn't check it drops the packet*/
			if (0 != checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len))) {
				continue;
			}

			/*TTL
			If the ttl is 0 or 1 (lower or equal 1) then the packet is dropped
			If not, the ttl is decremented*/
			if (ip_hdr->ttl <= 1) {
				
				/*ICMP Time excedeed*/



				/*Internet Header + 64 bits of Original Data Datagram */
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
				memcpy((char *)icmp_hdr + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);

				send_icmp_packet(ICMP_TYPE_TIME_EXCEDEED, buf, eth_hdr, ip_hdr, icmp_hdr, interface);
				continue;
				
			} else {
				ip_hdr->ttl = htons(ntohs(ip_hdr->ttl) - 1);
			}


			/*Searching the static ARP table*/
			uint8_t destination_not_found = 1;

			/*Searching rtable*/
			int rtable_index = binarySearch(rtable, 0, rtable_size - 1, ip_hdr->daddr);
			if (rtable_index >= 0) {
				destination_not_found = 0;
			}
			uint8_t destination_mac[6];
			get_interface_mac(rtable[rtable_index].interface, destination_mac);


		

			if (destination_not_found) {

				/*ICMP Destination Unreachable*/

				/*Internet Header + 64 bits of Original Data Datagram */
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
				memcpy((char *)icmp_hdr + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);
				
				send_icmp_packet(ICMP_TYPE_DEST_UNREACH, buf, eth_hdr, ip_hdr, icmp_hdr, interface);
				continue;
			}

			/*Recalculating checksum due to TTL change*/
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)(ip_hdr), ntohs(ip_hdr->tot_len)));


			int send_arp_request = 1;
			uint8_t next_hop_mac[6];
			for(int i = 0; i < arp_table_size; i++) {
				if (rtable[rtable_index].next_hop == arp_table[i].ip) {
					memcpy(next_hop_mac, arp_table[i].mac, sizeof(uint8_t) * 6);
					send_arp_request = 0;
					break;
				}
			}
			if (!send_arp_request) {
				memcpy(eth_hdr->ether_shost, destination_mac, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_dhost, next_hop_mac, sizeof(uint8_t) * 6);

				send_to_link(rtable[rtable_index].interface, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
			} else {
				struct packet *p = malloc(sizeof(struct packet));
				p->buf = malloc(sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
				memcpy(p->buf, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
				p->interface = rtable[rtable_index].interface;
				p->length = sizeof(struct ether_header) + ntohs(ip_hdr->tot_len);
				queue_enq(packet_queue, p);
				p->next_hop = rtable[rtable_index].next_hop;



				char *frame = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
				struct ether_header* eth = (struct ether_header*)frame;
				struct arp_header *arp = (struct arp_header *)(frame + sizeof(struct ether_header));
				eth->ether_type = htons(ETHER_TYPE_ARP);
				memcpy(eth->ether_shost, destination_mac, sizeof(uint8_t) * 6);
				for(int j = 0; j < 6; j++) {
					eth->ether_dhost[j] = 0xff;
				}
				arp->hlen = 6;
				arp->htype = htons(1);
				arp->op = htons(1);
				arp->plen = 4;
				arp->ptype = htons(ETHER_TYPE_IPV4);
				memcpy(arp->sha, destination_mac, sizeof(uint8_t) * 6);
				arp->spa = (inet_addr(get_interface_ip(rtable[rtable_index].interface)));
				for(int j = 0; j < 5; j++) {
					arp->tha[j] = htons(0x00);
				}
				arp->tpa = rtable[rtable_index].next_hop;
				send_to_link(rtable[rtable_index].interface, frame, sizeof(struct ether_header) + sizeof(struct arp_header));
				continue;
			}


		}

		/*Checks if EtherType is ARP*/
		if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {

			struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(struct ether_header));
			/*Checks if it is an ARP reply*/
			if (ntohs(arp_hdr->op) == 2) {
				arp_table[arp_table_size].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_size].mac, arp_hdr->sha, sizeof(uint8_t) * 6);
				arp_table_size++;


				//TODO: search in the queue and send packets with desired MAC
				struct packet *desired_packet;
				queue copy = queue_create();
				while(!queue_empty(packet_queue)) {
					desired_packet = queue_deq(packet_queue);
					struct ether_header *eth = (struct ether_header *)desired_packet->buf;
					struct iphdr *ip = (struct iphdr *)(desired_packet->buf + sizeof(struct ether_header));
					if (desired_packet->next_hop == arp_hdr->spa) {
						uint8_t source_mac[6];
						get_interface_mac(desired_packet->interface, source_mac);
						memcpy(eth->ether_shost, source_mac, sizeof(uint8_t) * 6);
						memcpy(eth->ether_dhost, arp_hdr->sha, sizeof(uint8_t) * 6);
						send_to_link(desired_packet->interface, desired_packet->buf, sizeof(struct ether_header) + ntohs(ip->tot_len));
					}
					queue_enq(copy, desired_packet);
				}
				packet_queue = copy;
			}

			/*Checks if is is an ARP request*/
			if (ntohs(arp_hdr->op) == 1) {
				/*Ignores the request if it is not for us*/
				if (arp_hdr->tpa != inet_addr(get_interface_ip(interface))) {
					continue;
				}
				/*Sending reply*/

				/*Ethernet header*/
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				memcpy(eth_hdr->ether_shost, interface_mac, sizeof(uint8_t) * 6);

				/*ARP Header*/
				arp_hdr->op = htons(2);
				arp_hdr->tpa = arp_hdr->spa;
				memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(uint8_t) * 6);
				arp_hdr->spa = ((inet_addr(get_interface_ip(interface))));
				memcpy(arp_hdr->sha, interface_mac, sizeof(uint8_t) * 6);

				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
			}
		}

	}
	free(arp_table);
	free(rtable);

}
