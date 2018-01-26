
#include "sniff-dmn.h"


unsigned long long bst_search(bst_tree *tree, unsigned int ip)
{
    bst_node *search_node;
    search_node = tree->root;
    while (1)
    {
        if (search_node == NULL)
            return 0;
        else if (search_node->ip == ip)
            return search_node->count;
        else if (search_node->ip < ip)
            search_node = search_node->right;
        else
            search_node = search_node->left;
    }
}

bst_node *bst_create_node(unsigned int ip, unsigned long long count)
{
    bst_node *new_node = (bst_node *)malloc(sizeof(bst_node));
    new_node->ip = ip;
    new_node->count = count;
    new_node->left = NULL;
    new_node->right = NULL;
    return new_node;
}

void bst_add_node(bst_tree *tree, unsigned int ip, unsigned long long count)
{
    if (tree->root == NULL)
    {
        tree->root = bst_create_node(ip, count);
        tree->count++;
        return;
    }

    bst_node *current = tree->root;

    while (current != NULL)
    {
        if (current->ip > ip)
        {
            if (current->left == NULL)
            {
                current->left = bst_create_node(ip, count);
                tree->count++;
                break;
            }
            current = current->left;
        }
        else if (current->ip < ip)
        {
            if (current->right == NULL)
            {
                current->right = bst_create_node(ip, count);
                tree->count++;
                break;
            }
            current = current->right;
        }
        else        // if current->ip == ip
        {
            current->count++;
            break;
        }
    }
}

void bst_print(bst_node *node)
{
    if (node->left != NULL)
        bst_print(node->left);
    printf("ip: %u, count: %llu\n", node->ip, node->count);
    if (node->right != NULL)
        bst_print(node->right);
}

void bst_free(bst_node *node)
{
    if (node == NULL)
        return;

    bst_free(node->left);
    bst_free(node->right);
    free(node);
}

void bst_to_list(list_node **head, bst_node *node)
{
    if (node->left != NULL && node != NULL)
        bst_to_list(head, node->left);
    if (node != NULL)
        add_node(head, node->ip, node->count);
    if (node->right != NULL && node != NULL)
        bst_to_list(head, node->right);
}
