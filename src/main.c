
#include "sniff-dmn.h"


int main(int argc, char *argv[])
{
    unsigned int iface;

    if (argc == 1)
        cli();
    else if (argc == 2 && !strcmp("start", argv[1]))
        start_sniffer_dmn(set_default_interface());
    else if (argc == 3 && !strcmp("start", argv[1]))
    {
        if ((iface = if_nametoindex(argv[2])))
            start_sniffer_dmn(iface);
        else
            printf("Invalid interface!\n");
    }
    else
        printf("Usage: %s [start [iface]]\n", argv[0]);

    exit(EXIT_SUCCESS);
}
