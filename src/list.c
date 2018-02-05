
#include "sniff-dmn.h"


list_node *get_last_node(list_node *head)
{
    if (head == NULL)
        return head;
    while (head->next)
        head = head->next;
    return head;
}

list_node *add_node(list_node **head, unsigned int ip, unsigned long long count)
{
    list_node *last_node = get_last_node((*head));
    list_node *new_node = (list_node *)malloc(sizeof(list_node));
    new_node->ip = ip;
    new_node->count = count;
    new_node->next = NULL;
    if (last_node)
        last_node->next = new_node;
    else
        (*head) = new_node;
    return new_node;
}

void list_free(list_node **head)
{
    list_node *del;
    if (*head == NULL)
        return;
    while (*head)
    {
        del = (*head);
        (*head) = (*head)->next;
        free(del);
    }
}

void print_list(list_node *head)
{
    struct sockaddr_in addr;
    while (head)
    {
        addr.sin_addr.s_addr = head->ip;
        printf("%-15s ----- %llu\n", inet_ntoa(addr.sin_addr), head->count);
        head = head->next;
    }
}
