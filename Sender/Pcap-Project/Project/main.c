// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: Predmetni Projekat (vezba9/vezba10)
// Radili: Branislav Gamf ra128-2015
//		   Dusan Kenjic ra130-2015
// ================================================================


// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define HAVE_STRUCT_TIMESPEC
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#include "file_manipulation.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>

pthread_mutex_t senderMutex;

pcap_t* deviceHandle;
unsigned char* packetData;
pcap_t* ethernetHandle;
pcap_t* wifiHandle;
char** dataFromFile;
FILE* f;
unsigned char packetKey[] = "12!@78&*";

unsigned long idForFirstTwoPackets = 0;
unsigned long idForEthPackets = 0;
unsigned long idForWifiPackets = 0;

unsigned long fileSize;
unsigned long sizeOfLastPacket;

int numOfPackets = 0;
int countEthernet = 0;
int countWifi = 0;
int flagEthernetWorks = 1;
int flagWifiWorks = 1;

unsigned long CURRENT_POSITION_OF_ETHERNET_FAILURE;
unsigned long CURRENT_POSITION_OF_WIFI_FAILURE;

/************/
void name_and_size_sending(unsigned char* inputFileName, unsigned char* packetData, unsigned char* numElemInFile, int lenOfPacket);
void ack_eth_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packetData);
void ack_wifi_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packetData);
void *wifi_thread_func(void *params);
void *eth_thread_func(void *params, int SOLP);
pcap_if_t* select_device(pcap_if_t* devices);
/***********/


int main()
{

	pthread_t wifiThread;
	pthread_t ethernetThread;

	pcap_if_t* devices;
	pcap_if_t* ethernet_device;
	pcap_if_t* wifi_device;

	int i;
	int lenOfPacket;
	int SOLP;
	int sizeOfEthHeader;
	int devNum;
	int sentBytes;

	char error_buffer[PCAP_ERRBUF_SIZE];

	//unsigned char* inputFileName = "song_test.mp3";
	unsigned char* inputFileName = "picture_test.jpg";
	//unsigned char* inputFileName = "tekst_test.txt";
	unsigned char* numElemInFile;
														
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	printf("Select first interface(ETHERNET): \n");
	ethernet_device = select_device(devices);
	if (ethernet_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}
	puts("");
	printf("Select second interface(WIFI): \n");
	wifi_device = select_device(devices);
	if (wifi_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/**************************************************************/
	/***** Open ethernet adapter *****/
	if ((ethernetHandle = pcap_open_live(ethernet_device->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", ethernet_device->name);
		return -1;
	}
	/**************************************************************/
	/***** Open wifi adapter *****/
	if ((wifiHandle = pcap_open_live(wifi_device->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", ethernet_device->name);
		return -1;
	}

	/**************************************************************/

	dataFromFile = read_from_file(f, dataFromFile, &numOfPackets, &SOLP);
	puts("Read from file successfully... \n");
	sizeOfLastPacket = SOLP;
	fileSize = (numOfPackets - 1) * DEFAULT_BUFLEN + sizeOfLastPacket;
	puts("");
	numElemInFile = convert_to_char(numOfPackets, &lenOfPacket);
	printf("Number of packets to send: %s\n", numElemInFile);
	puts("");
	printf("Sending data extension and number of packets...\n\n");

	pthread_mutex_init(&senderMutex, NULL);


	/*First, we must send name and size separately*/
	name_and_size_sending(inputFileName, packetData, numElemInFile, lenOfPacket);

	printf("Data extension sent and number of packets sent!\n\n");
	printf("ACK has been received!\n");
	printf("Sending data...\n");
	puts("");
	puts("***************************************************\n\n");
	puts("***************************************************\n\n");

	/****Creating thread for sending packets by ethernet or wifi****/

	pthread_create(&wifiThread, NULL, wifi_thread_func, NULL);
	pthread_create(&ethernetThread, NULL, eth_thread_func, NULL, SOLP);
	
	pthread_join(wifiThread, NULL);
	pthread_join(ethernetThread, NULL);

	printf("\n\nDATA SENT!\nNumber of sent packets is:  %d + first two packets(those packets are name and size)\n", numOfPackets);
	puts("");



	pcap_close(ethernetHandle);
	pcap_close(wifiHandle);
	free(packetData);
	free(dataFromFile);

	return 0;
}

/******************************************************************************************************************************/
void name_and_size_sending(unsigned char* inputFileName, unsigned char* packetData, unsigned char* numElemInFile, int lenOfPacket)
{
	for (int i = 0; i < 2; i++)
	{
		pthread_mutex_lock(&senderMutex);
		idForFirstTwoPackets = i + 1;
		pthread_mutex_unlock(&senderMutex);
		if (i == 0)
		{
			pthread_mutex_lock(&senderMutex);
			packetData = setup_header_ethernet(inputFileName, packetData, strlen(inputFileName) + 1, idForFirstTwoPackets);
			pthread_mutex_unlock(&senderMutex);

			if (pcap_sendpacket(ethernetHandle, packetData, strlen(inputFileName) + 1 + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Couldn't send %d. packet!\n", i);
				return -1;
			}
			puts("First packet is successfully sent!\n");
		}
		else
		{
			pthread_mutex_lock(&senderMutex);
			packetData = setup_header_ethernet(numElemInFile, packetData, strlen(numElemInFile) + 1, idForFirstTwoPackets);
			pthread_mutex_unlock(&senderMutex);

			if (pcap_sendpacket(ethernetHandle, packetData, lenOfPacket + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Couldn't send %d. packet!\n", i);
				return -1;
			}
			puts("Second packet is successfully sent!\n");
		}
	}
}

void ack_eth_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packetData)
{
	puts("Entered ethernet ACK!");
	printf("%d\n", idForEthPackets);
	ethernet_header * eh = (ethernet_header *)packetData;
	if (ntohs(eh->type) != 0x800)
	{
		printf("Not an ip packet!\n");
		return;
	}

	ip_header * ih = (ip_header *)(packetData + sizeof(ethernet_header));

	printf("%d\n", ih->next_protocol);
	if (ih->next_protocol != 17)
	{
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * customHeader = packetData + 42;	//string
	unsigned long num = (*(customHeader + 9) << 32) + (*(customHeader + 10) << 24) + (*(customHeader + 11) << 16) + (*(customHeader + 12) << 8) + *(customHeader + 13);

	//pthread_mutex_lock(&senderMutex);

	printf("ID of sent packet: %d\n", idForEthPackets);
	printf("Returned ID: %d\n", num);

	if (strcmp(customHeader, packetKey) == 0 && num == idForEthPackets)
	{
		Sleep(2);
		puts("Left Ethernet ACK!");
		pcap_breakloop(ethernetHandle);
	}
}

void ack_wifi_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packetData)
{
	puts("Entered WiFi ACK!");
	printf("%d\n", idForWifiPackets);
	ethernet_header * eh = (ethernet_header *)packetData;
	if (ntohs(eh->type) != 0x800)
	{
		printf("Not an ip packet!\n");
		return;
	}

	ip_header * ih = (ip_header *)(packetData + sizeof(ethernet_header));


	if (ih->next_protocol != 17)
	{
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * customHeader = packetData + 42;	//string
	unsigned long num = (*(customHeader + 9) << 32) + (*(customHeader + 10) << 24) + (*(customHeader + 11) << 16) + (*(customHeader + 12) << 8) + *(customHeader + 13);

	pthread_mutex_lock(&senderMutex);

	printf("ID of sent packet: %d\n", idForWifiPackets);
	printf("Returned ID: %d\n", num);

	if (strcmp(customHeader, packetKey) == 0 && num == idForWifiPackets)
	{
		Sleep(2);
		puts("Left WiFi ACK!");
		pcap_breakloop(wifiHandle);
	}
	pthread_mutex_unlock(&senderMutex);
}

pcap_if_t* select_device(pcap_if_t* devices)
{
	int devNum;
	int i = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;	// Iterator for device list

						// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &devNum);

	if (devNum < 1 || devNum > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i< devNum - 1; device = device->next, i++);

	return device;
}

void *wifi_thread_func(void *params)
{
	int i, j;
	unsigned char* packetData2;

	//for (i = 0; i < numOfPackets; i++)								// wifi onlyl
	for (i = numOfPackets / 2; i < numOfPackets; i++)				// half eth half wifi
	{
		puts("SENDING FILE OVER ----------------------------->  WIFI!");
		int len = DEFAULT_BUFLEN;

		if (i == numOfPackets - 1)
		{
			len = sizeOfLastPacket;
		}

		packetData2 = (char*)malloc(len);

		pthread_mutex_lock(&senderMutex);
		idForWifiPackets = i + 3;

		packetData2 = setup_header_wifi(dataFromFile[i], packetData2, len, idForWifiPackets);
		pthread_mutex_unlock(&senderMutex);

		if (numOfPackets - 1 == i)
			printf("POSLEDNJI: %d\n\n", len);

		if (pcap_sendpacket(wifiHandle, packetData2, len + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", i);
			break;
		}
		Sleep(2);

		/*Receive ACK for current packet*/
		while (pcap_loop(wifiHandle, 0, ack_wifi_handler, NULL) != -2)
		{
			puts("Sending packets again!\n\n");
			pcap_sendpacket(wifiHandle, packetData2, len);
			Sleep(2);
		}

		//if (i == numOfPackets)					// wifi only
		if (i == numOfPackets - 1)					// half eth half wifi
		{
			if (flagEthernetWorks == 0)
			{
				while (1)
				{
					puts("*******MAJOR FAILURE! ETHERNET DOWN! SENDING VIA WIFI!!!********\n\n");
					for (j = CURRENT_POSITION_OF_ETHERNET_FAILURE; j < numOfPackets / 2; j++)
					{
						puts("SENDING FILE OVER ----------------------------->  WIFI!");
						int len = DEFAULT_BUFLEN;

						if (j == (numOfPackets / 2 - 1))
						{
							len = sizeOfLastPacket;
						}

						packetData2 = (char*)malloc(len);

						pthread_mutex_lock(&senderMutex);
						idForWifiPackets = j + 3;

						packetData2 = setup_header_wifi(dataFromFile[i], packetData2, len, idForWifiPackets);
						pthread_mutex_unlock(&senderMutex);

						if (numOfPackets - 1 == j)
							printf("POSLEDNJI: %d\n\n", len);

						if (pcap_sendpacket(wifiHandle, packetData2, len + TOTAL_HEADER_SIZE) == -1)
						{
							printf("Packet %d not sent!\n", i);
							break;
						}
						Sleep(2);


						if (j == (numOfPackets / 2 - 1))
							break;
					}
				}
			}
		}
	}
}

void *eth_thread_func(void *params, int SOLP) {
	//for (int i = 0; i < numOfPackets; i++)				// ethenet only
	for (int i = 0; i < numOfPackets / 2; i++)		// half eth half wifi
	{
		flagEthernetWorks = 1;
		countEthernet = 0;

		puts("SENDING FILE OVER ----------------------------->  ETHERNET!");

		pthread_mutex_lock(&senderMutex);
		idForEthPackets = i + 3;
		pthread_mutex_unlock(&senderMutex);
		printf("\n\nIDDDDD %d\n", i);

		//if (i != numOfPackets)						// ethernet only
		if (i != numOfPackets - 1)						// half eth half wifi
		{
			pthread_mutex_lock(&senderMutex);
			packetData = setup_header_ethernet(dataFromFile[i], packetData, DEFAULT_BUFLEN, idForEthPackets);
			pthread_mutex_unlock(&senderMutex);
			puts("a");
			if (pcap_sendpacket(ethernetHandle, packetData, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);
			/*Receive ACK for current packet*/
			puts("D");
			while (pcap_loop(ethernetHandle, 0, ack_eth_handler, NULL) != -2)
			{
				countEthernet++;
				puts("+++");
				puts("Sending packets again!\n\n");
				pcap_sendpacket(ethernetHandle, packetData, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE);
				Sleep(2);

				if (countEthernet == 500)	//wait ten seconds
				{
					flagEthernetWorks = 0;
					break;
				}

			}
			if (flagEthernetWorks == 0)
			{
				CURRENT_POSITION_OF_ETHERNET_FAILURE = i;
				break;
			}
			puts("c");
		}
		else
		{
			pthread_mutex_lock(&senderMutex);
			packetData = setup_header_ethernet(dataFromFile[i], packetData, SOLP, idForEthPackets);
			pthread_mutex_unlock(&senderMutex);
			printf("\n*** Size of last: %d ***\n\n", SOLP + 56);

			if (pcap_sendpacket(ethernetHandle, packetData, SOLP + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);

			/*Receive ACK for current packet*/
			while (pcap_loop(ethernetHandle, 0, ack_eth_handler, NULL) != -2)
			{
				puts("Sending packets again!\n\n");
				pcap_sendpacket(ethernetHandle, packetData, SOLP + TOTAL_HEADER_SIZE);
				Sleep(2);
			}
		}
	}
}