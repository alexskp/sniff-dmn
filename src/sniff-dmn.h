
#ifndef _SNIFF_DMN_H
#define _SNIFF_DMN_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>         /* fork etc */
#include <string.h>
#include <errno.h>
#include <fcntl.h>          /* non blocking sockets */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>     /* definition of Ethernet header */
#include <linux/if_packet.h>    /* definition of IP header */
#include <linux/wireless.h>


#define DAEMON_DIR          "/sniff-dmn"
#define PID_FILE            "sniff-dmn.pid"
#define STAT_FILE           "sniff-dmn-stat.txt"
#define SOCKET_NAME         "socket"
#define BUFF_SIZE           100
#define PACKET_BUFF_SIZE    8192

typedef struct          node
{
    unsigned int        ip;
    unsigned long long  count;
    struct node         *left;
    struct node         *right;
} bst_node;

typedef struct          tree
{
    unsigned int        iface;
    int                 count;
    struct node         *root;
    struct tree         *next;
} bst_tree;

typedef struct          list_node
{
    unsigned int        ip;
    unsigned long long  count;
    struct list_node    *next;
} list_node;

/*
*  bst.c
*/
unsigned long long bst_search(bst_tree *tree, unsigned int ip);
void bst_print(bst_node *top_node);
bst_node *bst_create_node(unsigned int ip, unsigned long long count);
void bst_add_node(bst_tree *tree, unsigned int ip, unsigned long long count);
void bst_free(bst_node *node);
void bst_to_list(list_node **head, bst_node *node);

/*
*  bst_list.c
*/
bst_tree *bst_get_last_tree(bst_tree *head);
bst_tree *bst_get_tree(bst_tree *head, unsigned int iface);
bst_tree *bst_create_tree(unsigned int iface);
bst_tree *bst_add_tree(bst_tree **head, unsigned int iface);
void bst_add_existing_tree(bst_tree **head, bst_tree *tree);
void bst_list_free(bst_tree **head);

/*
*  bst_file.c
*/
void bst_nodes_tofile(bst_node *top_node, int mode, FILE *fptr);
void bst_to_file(bst_tree *tree, const char *path);
int search(unsigned int arr[], int start, int end, unsigned int value);
bst_node *bst_nodes_fromfile(unsigned int in[], unsigned int pre[], unsigned long long count[], int start, int end);
bst_tree *bst_fromfile(const char *path);

/*
*  sniffer.c
*/
int server(int client_socket, bst_tree *tree, unsigned int iface);
void sniffer(unsigned int iface);

/*
*  cli.c
*/
void cli(void);
void start_sniffer_dmn(unsigned int iface);
void print_help(void);
int request_to_daemon(const char *msg);
void set_work_dir(void);

/*
*  list.c
*/
list_node *get_last_node(list_node *head);
list_node *add_node(list_node **head, unsigned int ip, unsigned long long count);
void list_free(list_node **head);
void print_list(list_node *head);

/*
*  tools.c
*/
int check_wireless(const char* ifname);         // check if interface is wireless for setting wired interface as default
unsigned int set_default_interface(void);
void list_devices(void);

#endif
