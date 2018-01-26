
#include "sniff-dmn.h"


bst_tree *bst_get_last_tree(bst_tree *head)
{
    if (head == NULL)
        return head;
    while (head->next)
        head = head->next;
    return head;
}

bst_tree *bst_get_tree(bst_tree *head, unsigned int iface)
{
    while (head)
    {
        if (head->iface == iface)
            return head;
        else
            head = head->next;
    }
    return NULL;
}

bst_tree *bst_create_tree(unsigned int iface)
{
    bst_tree *new_tree = (bst_tree *)malloc(sizeof(bst_tree));
    new_tree->iface = iface;
    new_tree->count = 0;
    new_tree->root = NULL;
    new_tree->next = NULL;
    return new_tree;
}

bst_tree *bst_add_tree(bst_tree **head, unsigned int iface)
{
    if (!bst_get_tree((*head), iface))
    {
        bst_tree *last_tree = bst_get_last_tree((*head));
        bst_tree *new_tree = bst_create_tree(iface);
        if (last_tree)
            last_tree->next = new_tree;
        else
            (*head) = new_tree;
        return new_tree;
    }
    else
        return NULL;
}

void bst_add_existing_tree(bst_tree **head, bst_tree *tree)
{
    bst_tree *last_tree = bst_get_last_tree((*head));
    if (last_tree)
        last_tree->next = tree;
    else
        (*head) = tree;
}

void bst_list_free(bst_tree **head)
{
    bst_tree *del;
    if (*head == NULL)
        return;
    while (*head)
    {
        bst_free((*head)->root);
        del = (*head);
        (*head) = (*head)->next;
        free(del);
    }
}
