
#include "sniff-dmn.h"

#define INORDER     0
#define PREORDER    1

int pre_index = 0;

void bst_nodes_tofile(bst_node *node, int mode, FILE *fptr)
{
    if (mode == INORDER)
    {
        if (node->left != NULL)
            bst_nodes_tofile(node->left, mode, fptr);
        fprintf(fptr, "%u\n", node->ip);
        if (node->right != NULL)
            bst_nodes_tofile(node->right, mode, fptr);
    }
    else
    {
        fprintf(fptr, "%u: %llu\n", node->ip, node->count);
        if (node->left != NULL)
            bst_nodes_tofile(node->left, mode, fptr);
        if (node->right != NULL)
            bst_nodes_tofile(node->right, mode, fptr);
    }
}

void bst_to_file(bst_tree *tree, const char *path)
{
    int num_of_trees = 0;
    bst_tree *current = tree;
    FILE *fptr;

    while (current)
    {
        current = current->next;
        num_of_trees++;
    }

    fptr = fopen(path, "w");
    if (fptr == NULL)
        exit(EXIT_FAILURE);

    for (int i = 0; i < num_of_trees; i++)
    {
        fprintf(fptr, "#iface: %u, count: %i\n", tree->iface, tree->count);
        bst_nodes_tofile(tree->root, PREORDER, fptr);
        bst_nodes_tofile(tree->root, INORDER, fptr);
        tree = tree->next;
    }

    fclose(fptr);
}

int search(unsigned int arr[], int start, int end, unsigned int value)
{
    int i;
    for (i = start; i <= end; i++)
    {
        if(arr[i] == value)
        return i;
    }
    return -1;
}

bst_node *bst_nodes_fromfile(unsigned int in[], unsigned int pre[], unsigned long long count[], int start, int end)
{
    if(start > end)
        return NULL;

    /* Pick current node from Preorder traversal using pre_index
    and increment pre_index */
    bst_node *node = bst_create_node(pre[pre_index], count[pre_index]);
    pre_index++;

    /* If this node has no children then return */
    if(start == end)
    return node;

    /* Else find the index of this node in Inorder traversal */
    int in_index = search(in, start, end, node->ip);

    /* Using index in Inorder traversal, construct left and
     right subtrees */
    node->left = bst_nodes_fromfile(in, pre, count, start, in_index - 1);
    node->right = bst_nodes_fromfile(in, pre, count, in_index + 1, end);

    return node;
}

bst_tree *bst_fromfile(const char *path)
{
    FILE *fptr;
    char c;
    int num_of_trees = 0;
    int num_of_nodes;
    unsigned int iface;
    long int pos = 0;

    bst_tree *head = NULL;

    fptr = fopen(path, "r");
    if (fptr == NULL)
        return NULL;

    while ((c = fgetc(fptr)) != EOF)
    {
        if (c == '#')
            num_of_trees++;
    }

    char buff[BUFF_SIZE];
    fseek(fptr, pos, SEEK_SET);

    if (num_of_trees == 0)
        return NULL;

    for (int j = 0; j < num_of_trees; j++)
    {
        fgets(buff, BUFF_SIZE, fptr);

        sscanf(buff, "#iface: %u, count: %i\n", &iface, &num_of_nodes);

        unsigned int *preorder = (unsigned int *)malloc(num_of_nodes * sizeof(unsigned int));
        unsigned int *inorder = (unsigned int *)malloc(num_of_nodes * sizeof(unsigned int));
        unsigned long long *count = (unsigned long long *)malloc(num_of_nodes * sizeof(unsigned long long));

        for (int i = 0; i < num_of_nodes; i++)
        {
            fgets(buff, BUFF_SIZE, fptr);
            sscanf(buff, "%u: %llu", &preorder[i], &count[i]);
        }
        for (int i = 0; i < num_of_nodes; i++)
        {
            fgets(buff, BUFF_SIZE, fptr);
            sscanf(buff, "%u", &inorder[i]);
        }

        bst_tree *tree = (bst_tree *)malloc(sizeof(bst_tree));
        tree->iface = iface;
        tree->count = num_of_nodes;
        tree->next = NULL;
        tree->root = bst_nodes_fromfile(inorder, preorder, count, 0, num_of_nodes - 1);
        pre_index = 0;

        bst_add_existing_tree(&head, tree);

        free(preorder);
        free(inorder);
        free(count);
    }

    fclose(fptr);
    return head;
}
