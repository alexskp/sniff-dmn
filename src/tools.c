
#include "sniff-dmn.h"


int check_wireless(const char* ifname)
{
	int sock;
	struct iwreq pwrq;

	memset(&pwrq, 0, sizeof(pwrq));
	strncpy(pwrq.ifr_name, ifname, IFNAMSIZ);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		return 0;
	}

	if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1)
	{
		close(sock);
		return 1;
	}
	close(sock);
	return 0;
}

unsigned int set_default_interface()
{
	/*
	 * set default interface to wired interface with smaller index
	 */
	struct ifaddrs *addrs, *tmp;
	unsigned int ifindex = 0;
    unsigned int tmp_ifindex;

	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		    !check_wireless(tmp->ifa_name) && !(tmp->ifa_flags & IFF_LOOPBACK))
		{
			tmp_ifindex = if_nametoindex(tmp->ifa_name);

			if (ifindex == 0)
				ifindex = tmp_ifindex;
			else if (ifindex > tmp_ifindex)
				ifindex = tmp_ifindex;
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
    return ifindex;
}

void list_devices()
{
	struct ifaddrs *addrs, *tmp;

	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
			printf("%s\n", tmp->ifa_name);
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
}
