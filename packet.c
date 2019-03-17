#include <stdio.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <pcap.h>

#define TCPDUMP_MAGIC (0xA1B2C3D4)

static int openNetworkInterface(char *ifname);

int main(int argc, char **argv) {
	int sock;
	unsigned char recvBuf[1024*128];
	FILE *fpPcap;
	struct pcap_file_header pcapHeader;

	if (argc < 2) {
		fprintf(stderr, "must specify interface name.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "%s\n", argv[1]);
	sock = openNetworkInterface(argv[1]);
	if (sock < 0) {
		fprintf(stderr, "Open Interface [%s] failed.", argv[1]);
		exit(EXIT_FAILURE);
	}

	fpPcap = fopen("dump.pcap","wb");
	if (fpPcap == NULL)
	{
		fprintf(stderr, "Open Interface [%s] failed.", argv[1]);
		close(sock);
		exit(EXIT_FAILURE);
	}

	memset(&pcapHeader, 0, sizeof(struct pcap_file_header));
	pcapHeader.magic = TCPDUMP_MAGIC;
	pcapHeader.version_major = PCAP_VERSION_MAJOR;
	pcapHeader.version_minor = PCAP_VERSION_MINOR;
	pcapHeader.snaplen = 2048;
	pcapHeader.sigfigs = 0;
	pcapHeader.linktype = DLT_EN10MB;
	fwrite(&pcapHeader, sizeof(struct pcap_file_header), 1, fpPcap);
	while(1) {
		int recvSize;
		struct pcap_pkthdr pktHeader;

		recvSize = read(sock, recvBuf, sizeof(recvBuf));
		if (recvSize < 0)
		{
			fprintf(stderr, "read error [%d]\n", recvSize);
			continue;
		}

		fprintf(stdout, "recvSize:[%d]\n", recvSize);
		memset(&pktHeader, 0, sizeof(struct pcap_pkthdr));

		gettimeofday(&(pktHeader.ts), NULL);
		pktHeader.caplen = recvSize;
		pktHeader.len = recvSize;

		fwrite(&pktHeader, sizeof(struct pcap_pkthdr), 1, fpPcap);
		fwrite(recvBuf, recvSize, 1, fpPcap);
	}

	close(sock);
	fclose(fpPcap);
	exit(EXIT_SUCCESS);
}

int openNetworkInterface(char *ifname) {
	int ret;
	int sock;
	struct ifreq ifreq;
	struct sockaddr_ll sa;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "socket failed %d\n", sock);
		return -1;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name)-1);

	ret = ioctl(sock, SIOCGIFINDEX, &ifreq);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed [%d]\n", ret);
		close(sock);
		return -1;
	}

	sa.sll_family=PF_PACKET;
	sa.sll_protocol=htons(ETH_P_ALL);
	sa.sll_ifindex=ifreq.ifr_ifindex;

	ret = bind(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		fprintf(stderr, "bind failed [%d]\n", ret);
		close(sock);
		return -1;
	}

	return sock;
}