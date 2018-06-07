#include "protocol_headers.h"
#include "file_manipulation.h"


/*protocol info*/
unsigned char srcMacEthAddr[] = { 0x2c, 0x4d, 0x54, 0xd0, 0xef, 0xd7 };	
unsigned char srcMacWifiAddr[] = { 0x00, 0x0f, 0x60, 0x06, 0x1f, 0x50 };	

unsigned char dstMacEthAddr[] = { 0x2c, 0x4d, 0x54, 0x56, 0x99, 0x17 };
unsigned char dstMacWifiAddr[] = { 0x00, 0x0f, 0x60, 0x08, 0x1e, 0x5e };		


unsigned char nextProtocolHeaderIpv4[2] = { 0x08, 0x00 };
unsigned int nextProtocolHeaderUdp = 17;

unsigned char dstIpEthAddr[] = { 192, 168, 212, 1 };						
unsigned char srcIpEthAddr[] = { 192, 168, 106, 1 };						

unsigned char dstIpWifiAddr[] = { 192, 168, 123, 1 };							
unsigned char srcIpWifiAddr[] = { 192, 168, 123, 18 };						


/*Functions*/
unsigned short calculate_checksum(unsigned char* header);
unsigned char* setup_header_ethernet(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber);
unsigned char* setup_header_wifi(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber);
/***********/

unsigned char* setup_header_ethernet(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber)
{
	unsigned int len;
	if (size_of_current_package != DEFAULT_BUFLEN)
	{
		len = TOTAL_HEADER_SIZE + size_of_current_package;
	}
	else
	{
		len = TOTAL_HEADER_SIZE + DEFAULT_BUFLEN;
	}
	unsigned char* header = (unsigned char*)realloc(passed_header, len);
	unsigned short ret_ip_checksum;
	unsigned int just_udp_size = len - ETHERNET_HEADER_SIZE - IP_SIZE;

	/*SETUP ETHERNET HEADER*/
	for (int i = 0; i < 6; i++)
	{
		header[i] = dstMacEthAddr[i];
		header[i + 6] = srcMacEthAddr[i];
	}

	header[12] = (unsigned char)0x8;
	header[13] = (unsigned char)0x00;

	/*SETUP IP HEADER*/
	header[ETHERNET_HEADER_SIZE] = (unsigned char)0x45; //version & IHL
	header[ETHERNET_HEADER_SIZE + 1] = (unsigned char)0x00; //tos
	header[ETHERNET_HEADER_SIZE + 2] = (unsigned char)(len-ETHERNET_HEADER_SIZE >> 8);//Total len in hex, first part
	header[ETHERNET_HEADER_SIZE + 3] = (unsigned char)(len - ETHERNET_HEADER_SIZE & 0xff);// total len in hex, second part
	header[ETHERNET_HEADER_SIZE + 4] = (unsigned char)0x00; //identification first part
	header[ETHERNET_HEADER_SIZE + 5] = (unsigned char)0x00; //identification second part
	header[ETHERNET_HEADER_SIZE + 6] = (unsigned char)0x40;//flags
	header[ETHERNET_HEADER_SIZE + 7] = (unsigned char)0x00;//offset
	header[ETHERNET_HEADER_SIZE + 8] = (unsigned char)0x1e;//ttl
	header[ETHERNET_HEADER_SIZE + 9] = (unsigned char)0x11; //next protocol
	header[ETHERNET_HEADER_SIZE + 12] = (unsigned char)srcIpEthAddr[0];//src ip pt1
	header[ETHERNET_HEADER_SIZE + 13] = (unsigned char)srcIpEthAddr[1];//src ip pt2
	header[ETHERNET_HEADER_SIZE + 14] = (unsigned char)srcIpEthAddr[2];//src ip pt3
	header[ETHERNET_HEADER_SIZE + 15] = (unsigned char)srcIpEthAddr[3];//src ip pt4
	header[ETHERNET_HEADER_SIZE + 16] = (unsigned char)dstIpEthAddr[0];//dst ip pt1
	header[ETHERNET_HEADER_SIZE + 17] = (unsigned char)dstIpEthAddr[1];//dst ip pt2
	header[ETHERNET_HEADER_SIZE + 18] = (unsigned char)dstIpEthAddr[2];//dst ip pt3
	header[ETHERNET_HEADER_SIZE + 19] = (unsigned char)dstIpEthAddr[3];//dst ip pt4
	header[ETHERNET_HEADER_SIZE + 10] = 0;//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = 0; //second part of header checksum

	ret_ip_checksum = 0;
	ret_ip_checksum = calculate_checksum(header);

	header[ETHERNET_HEADER_SIZE + 10] = (unsigned char)(ret_ip_checksum >> 8);//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = (unsigned char)(ret_ip_checksum & 0x00ff); //second part of header checksum

	/*SETUP UDP HEADER*/
	header[ETHERNET_HEADER_SIZE + IP_SIZE] = (unsigned char)(SOURCE_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 1] = (unsigned char)(SOURCE_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 2] = (unsigned char)(DESTINATION_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 3] = (unsigned char)(DESTINATION_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 4] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 5] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 6] = (unsigned char) 0x00;
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 7] = (unsigned char) 0x00;



	//******************************************//******************************************
	unsigned char packetKey[] = "12!@78&*";

	for (int i = ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE; i <= ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 13; i++)	//len is 564
	{
		header[i] = 0;
	}

	//memcpy(header, packetKey, 9);
	//******************************************//******************************************
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 0] = 'O';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 1] = 'R';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 2] = 'M';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 3] = '2';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 4] = 'P';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 5] = 'r';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 6] = 'o';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 7] = 'j';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 8] = '\0';

	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 9] = (unsigned char)((orderNumber & 0xFF00000000) >> 32);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 10] = (unsigned char)((orderNumber & 0xFF000000) >> 24);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 11] = (unsigned char)((orderNumber & 0xFF0000) >> 16);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 12] = (unsigned char)((orderNumber & 0xFF00) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 13] = (unsigned char)(orderNumber & 0xFF);



	for (int i = ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 14, j = 0; i < len; i++, j++)
	{
		header[i] = data_buffer[j];
	}


	return header;
}

unsigned char* setup_header_wifi(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber)
{
	unsigned int len;
	if (size_of_current_package != DEFAULT_BUFLEN)
	{
		len = TOTAL_HEADER_SIZE + size_of_current_package;
	}
	else
	{
		len = TOTAL_HEADER_SIZE + DEFAULT_BUFLEN;
	}
	unsigned char* header = (unsigned char*)realloc(passed_header, len);
	unsigned short ret_ip_checksum;
	unsigned int just_udp_size = len - ETHERNET_HEADER_SIZE - IP_SIZE;

	/*SETUP ETHERNET HEADER*/
	for (int i = 0; i < 6; i++)
	{
		header[i] = dstMacWifiAddr[i];
		header[i + 6] = srcMacWifiAddr[i];
	}

	header[12] = (unsigned char)0x8;
	header[13] = (unsigned char)0x00;

	/*SETUP IP HEADER*/
	header[ETHERNET_HEADER_SIZE] = (unsigned char)0x45; //version & IHL
	header[ETHERNET_HEADER_SIZE + 1] = (unsigned char)0x00; //tos
	header[ETHERNET_HEADER_SIZE + 2] = (unsigned char)(len - ETHERNET_HEADER_SIZE >> 8);//Total len in hex, first part
	header[ETHERNET_HEADER_SIZE + 3] = (unsigned char)(len - ETHERNET_HEADER_SIZE & 0xff);// total len in hex, second part
	header[ETHERNET_HEADER_SIZE + 4] = (unsigned char)0x00; //identification first part
	header[ETHERNET_HEADER_SIZE + 5] = (unsigned char)0x00; //identification second part
	header[ETHERNET_HEADER_SIZE + 6] = (unsigned char)0x40;//flags
	header[ETHERNET_HEADER_SIZE + 7] = (unsigned char)0x00;//offset
	header[ETHERNET_HEADER_SIZE + 8] = (unsigned char)0x1e;//ttl
	header[ETHERNET_HEADER_SIZE + 9] = (unsigned char)0x11; //next protocol
	header[ETHERNET_HEADER_SIZE + 12] = (unsigned char)srcIpWifiAddr[0];//src ip pt1
	header[ETHERNET_HEADER_SIZE + 13] = (unsigned char)srcIpWifiAddr[1];//src ip pt2
	header[ETHERNET_HEADER_SIZE + 14] = (unsigned char)srcIpWifiAddr[2];//src ip pt3
	header[ETHERNET_HEADER_SIZE + 15] = (unsigned char)srcIpWifiAddr[3];//src ip pt4
	header[ETHERNET_HEADER_SIZE + 16] = (unsigned char)dstIpWifiAddr[0];//dst ip pt1
	header[ETHERNET_HEADER_SIZE + 17] = (unsigned char)dstIpWifiAddr[1];//dst ip pt2
	header[ETHERNET_HEADER_SIZE + 18] = (unsigned char)dstIpWifiAddr[2];//dst ip pt3
	header[ETHERNET_HEADER_SIZE + 19] = (unsigned char)dstIpWifiAddr[3];//dst ip pt4
	header[ETHERNET_HEADER_SIZE + 10] = 0;//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = 0; //second part of header checksum

	ret_ip_checksum = 0;
	ret_ip_checksum = calculate_checksum(header);

	header[ETHERNET_HEADER_SIZE + 10] = (unsigned char)(ret_ip_checksum >> 8);//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = (unsigned char)(ret_ip_checksum & 0x00ff); //second part of header checksum

																				   /*SETUP UDP HEADER*/
	header[ETHERNET_HEADER_SIZE + IP_SIZE] = (unsigned char)(SOURCE_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 1] = (unsigned char)(SOURCE_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 2] = (unsigned char)(DESTINATION_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 3] = (unsigned char)(DESTINATION_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 4] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 5] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 6] = (unsigned char)0x00;
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 7] = (unsigned char)0x00;



	//******************************************//******************************************
	unsigned char packetKey[] = "12!@78&*";

	for (int i = ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE; i <= ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 13; i++)	//len is 564
	{
		header[i] = 0;
	}

	//memcpy(header, packetKey, 9);
	//******************************************//******************************************
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 0] = 'O';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 1] = 'R';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 2] = 'M';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 3] = '2';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 4] = 'P';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 5] = 'r';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 6] = 'o';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 7] = 'j';
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 8] = '\0';

	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 9] = (unsigned char)((orderNumber & 0xFF00000000) >> 32);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 10] = (unsigned char)((orderNumber & 0xFF000000) >> 24);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 11] = (unsigned char)((orderNumber & 0xFF0000) >> 16);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 12] = (unsigned char)((orderNumber & 0xFF00) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 13] = (unsigned char)(orderNumber & 0xFF);



	for (int i = ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 14, j = 0; i < len; i++, j++)
	{
		header[i] = data_buffer[j];
	}


	return header;
}


unsigned short calculate_checksum(unsigned char* header)
{
	unsigned int header_checksum_calc = 0;

	for (int i = ETHERNET_HEADER_SIZE; i < ETHERNET_HEADER_SIZE + 20; i += 2)
	{
		header_checksum_calc += (header[i] << 8) + header[i + 1];
	}


	while (header_checksum_calc & 0xF0000)
	{
		unsigned int temp = (header_checksum_calc >> 16) + (header_checksum_calc & 0xFFFF);
		header_checksum_calc = temp;
	}

	header_checksum_calc = ~(header_checksum_calc);

	return (unsigned short)header_checksum_calc;
}
