#pragma once
/**** UDP header ****/
#define udp_src_port 8080
#define udp_dst_port 8080
#define udp_h_size 8
/*******************/

/**** IPv4 header ****/
#define version 4
#define IHL 5
#define TOS 0
#define identification 0
#define FlagsAndOffset 0x4000
#define TTL 30
#define nxt_protocol 17			//UDP
/*********************/

/**** Ethernet ****/
#define preamble 0b10101010
#define SFD 0b10101011
#define np_type 0x0800			//ipv4
#define eth_h_size 14
/******************/



unsigned short ipv4_header_checksum(unsigned char * packet_data);
unsigned char * udp_header_checksum(unsigned char * packet_data, unsigned int * len);
unsigned char * setup_ethernet_header(unsigned int * len, unsigned char * packet_data, int flag);
unsigned char * setup_ipv4_header(unsigned int * len, unsigned char * packet_data, int flag);
unsigned char * setup_udp_header(unsigned int * len, unsigned char * packet_data);
unsigned char * setup_custom_header(unsigned int * len, unsigned char * packet_data, long order_number);

const unsigned char dst_mac_address[] = { 0x2c, 0x4d, 0x54, 0xd0, 0xef, 0xd7 };			//Ethernet Bane (sender)
const unsigned char dst_mac_address_wifi[] = { 0x00, 0x0f, 0x60, 0x06, 0x1f, 0x50 };	//WiFi Bane (sender)

const unsigned char src_mac_address[] = { 0x2c, 0x4d, 0x54, 0x56, 0x99, 0x17 };			//Ethernet Stevan (receiver)
const unsigned char src_mac_address_wifi[] = { 0x00, 0x0f, 0x60, 0x08, 0x1e, 0x5e };	//WiFi Stevan (receiver)

const unsigned char dst_ipv4_address[] = { 192, 168, 106, 1 };							//Ethernet Bane (sender)
const unsigned char src_ipv4_address[] = { 192, 168, 212, 1 };							//Ethernet Stevan (receiver)

const unsigned char dst_ipv4_address_wifi[] = { 192, 168, 123, 18 };					//WiFi Bane (sender)
const unsigned char src_ipv4_address_wifi[] = { 192, 168, 123, 1 };						//WiFi Stevan (receiver)