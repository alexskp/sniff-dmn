
#include "sniff-dmn.h"

int server(int client_socket, bst_tree *tree, unsigned int iface)
{
    char buff[BUFF_SIZE];
    char sep[] = " ";

	while (1)
    {
		if (read(client_socket, buff, BUFF_SIZE) == 0)
			return 0;

        if (!strcmp("stop", buff))
        {
            strcpy(buff, "end");
            write(client_socket, buff, BUFF_SIZE);
            return 1;
        }
        else if (!strcmp("stat", buff))
        {
            struct sockaddr_in addr;
            bst_tree *current_tree = tree;

            while (current_tree)
            {
                list_node *list = NULL;
                char ifname[IF_NAMESIZE];

                if_indextoname(current_tree->iface, ifname);
                sprintf(buff, "\ninteface: %s", ifname);
                write(client_socket, buff, BUFF_SIZE);
                sprintf(buff, " IP:\t\tpacket(s)\n-------------------------");
                write(client_socket, buff, BUFF_SIZE);

                if (current_tree->root != NULL)
                    bst_to_list(&list, current_tree->root);

                while (list)
                {
                    addr.sin_addr.s_addr = list->ip;
                    sprintf(buff, "%-15s ----- %llu", inet_ntoa(addr.sin_addr), list->count);
                    write(client_socket, buff, BUFF_SIZE);
                    list = list->next;
                }
                current_tree = current_tree->next;
                list_free(&list);
            }
            strcpy(buff, "end");
            write(client_socket, buff, BUFF_SIZE);
            return 0;
        }
        else if (!strncmp("stat", buff, 4))
        {
            strtok(buff, sep);
            char *iface = strtok(NULL, sep);
            char ifname[IF_NAMESIZE];
            struct sockaddr_in addr;
            list_node *list = NULL;

            unsigned int interface;
            if (!(interface = if_nametoindex(iface)))
            {
                strcpy(buff, "Invalid interface");
                write(client_socket, buff, BUFF_SIZE);
                strcpy(buff, "end");
                write(client_socket, buff, BUFF_SIZE);
                return 0;
            }

            bst_tree *current_tree = bst_get_tree(tree, interface);

            if (current_tree->root != NULL)
                bst_to_list(&list, current_tree->root);

            if_indextoname(current_tree->iface, ifname);
            sprintf(buff, "\ninteface: %s", ifname);
            write(client_socket, buff, BUFF_SIZE);
            sprintf(buff, " IP:\t\tpacket(s)\n-------------------------");
            write(client_socket, buff, BUFF_SIZE);

            while (list)
            {
                addr.sin_addr.s_addr = list->ip;
                sprintf(buff, "%-15s ----- %llu", inet_ntoa(addr.sin_addr), list->count);
                write(client_socket, buff, BUFF_SIZE);
                list = list->next;
            }
            list_free(&list);

            strcpy(buff, "end");
            write(client_socket, buff, BUFF_SIZE);
            return 0;
        }
        else if (!strncmp("show", buff, 4))
        {
            strtok(buff, sep);
            char *ip = strtok(NULL, sep);

            int count;
            struct sockaddr_in addr;
            inet_aton(ip, &addr.sin_addr);

            bst_tree *current_tree = bst_get_tree(tree, iface);
            count = bst_search(current_tree, addr.sin_addr.s_addr);
            sprintf(buff, "%-15s ----- %u packet(s)", ip, count);

            write(client_socket, buff, BUFF_SIZE);
            strcpy(buff, "end");
            write(client_socket, buff, BUFF_SIZE);
            return 0;
        }
        else
        {
            strcpy(buff, "end");
            write(client_socket, buff, BUFF_SIZE);
            return 0;
        }
    }
}

void sniffer(unsigned int iface)
{
    struct sockaddr_ll my_addr;
    int sock_raw;

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    fcntl(sock_raw, F_SETFL, O_NONBLOCK);
    if(sock_raw < 0)
        exit(EXIT_FAILURE);

    /* Clear structure */
    memset(&my_addr, 0, sizeof(struct sockaddr_ll));

    my_addr.sll_family = AF_PACKET;
    my_addr.sll_ifindex = iface;

    if (bind(sock_raw, (struct sockaddr *) &my_addr, sizeof(struct sockaddr_ll)) < 0)
        exit(EXIT_FAILURE);


    char *buffer = (char *)malloc(PACKET_BUFF_SIZE); //to receive data
    memset(buffer, 0, PACKET_BUFF_SIZE);

    struct      sockaddr saddr;
    int         saddr_len = sizeof(saddr);
    int         buflen;
    struct      iphdr *ip;

    int                socket_fd;
	struct             sockaddr_un name;
	int                client_sent_quit_message = 0;

    struct sockaddr_un client_name;
    socklen_t          client_name_len;
    int                client_socket_fd;

    unlink(SOCKET_NAME);
    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    name.sun_family = AF_UNIX;
	strcpy(name.sun_path, SOCKET_NAME);
    bind(socket_fd, (struct sockaddr *)&name, SUN_LEN (&name));
	listen(socket_fd, 5);


    bst_tree *tree_list = bst_fromfile(STAT_FILE);
    bst_add_tree(&tree_list, iface);
    bst_tree *current_tree = bst_get_tree(tree_list, iface);

    do {
        //Receive a network packet and copy in to buffer
        buflen = recvfrom(sock_raw, buffer, PACKET_BUFF_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        if(buflen > 0)
        {
            ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            bst_add_node(current_tree, ip->saddr, 1);
        }

        /* Accept a connection.  */
		client_socket_fd = accept(socket_fd, (struct sockaddr *)&client_name, &client_name_len);
		/* Handle the connection.  */
        if (client_socket_fd > 0)
        {
            client_sent_quit_message = server(client_socket_fd, tree_list, iface);
        }
		/* Close connection.  */
		close(client_socket_fd);
	} while (!client_sent_quit_message);

    bst_to_file(tree_list, STAT_FILE);

    close(socket_fd);
    unlink(SOCKET_NAME);
}
