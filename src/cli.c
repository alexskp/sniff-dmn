
#include "sniff-dmn.h"

#define DAEMON_ON       1
#define DAEMON_OFF      0

#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void cli(void)
{
    char buff[BUFF_SIZE];
    char *word1;
    char *word2;
    char *word3;
    char sep[] = " \n\t";

    int daemon_status = DAEMON_OFF;

    unsigned int iface;
    iface = set_default_interface();

    set_work_dir();

    printf(ANSI_COLOR_GREEN "sniff-dmn> " ANSI_COLOR_RESET);

    while (fgets(buff, BUFF_SIZE, stdin) != NULL)
    {
        word1 = strtok(buff, sep);
        word2 = strtok(NULL, sep);
        word3 = strtok(NULL, sep);

        if (word1 && !word2 && !word3 && !strcmp("start", word1))
        {
            if (!daemon_status)
            {
                start_sniffer_dmn(iface);
                daemon_status = DAEMON_ON;
                char ifname[IF_NAMESIZE];
                if_indextoname(iface, ifname);
                printf("Sniffing on %s\n", ifname);
            }
            else
                printf("Sniffer is already on\n");
        }
        else if (word1 && !word2 && !word3 && !strcmp("stop", word1))
        {
            if (!request_to_daemon("stop"))
                printf("Sniffer is already stopped\n");
            else
            {
                daemon_status = DAEMON_OFF;
                printf("Sniffer is stopped\n");
            }
        }
        else if (word1 && word2 && word3 && !strcmp("show", word1) && !strcmp("count", word3))
        {
            char ip[20];
            strcpy(ip, word2);
            strcpy(buff, "show ");
            strcat(buff, ip);
            if (!request_to_daemon(buff))
                printf("Sniffer is off\n");
        }
        else if (word1 && word2 && !word3 && !strcmp("stat", word1))
        {
            char if_name[20];
            strcpy(if_name, word2);
            strcpy(buff, "stat ");
            strcat(buff, if_name);
            if (!request_to_daemon(buff))
                printf("Sniffer is off\n");
        }
        else if (word1 && !word2 && !word3 && !strcmp("stat", word1))
        {
            if (!request_to_daemon("stat"))
                printf("Sniffer is off\n");
        }
        else if (word1 && word2 && word3 && !strcmp("select", word1) && !strcmp("iface", word2))
        {
            unsigned int interface;
            if ((interface = if_nametoindex(word3)))
            {
                iface = interface;
                printf("%s interface selected. Restart to use\n", word3);
            }
            else
                printf("Invalid interface!\n");
        }
        else if (word1 && word2 && !word3 && !strcmp("iface", word1) && !strcmp("list", word2))
        {
            printf("avaliable interfaces:\n");
            list_devices();
        }
        else if (word1 && !word2 && !word3 && (!strcmp("quit", word1) || !strcmp("q", word1)))
            exit(EXIT_SUCCESS);
        else if (word1 && !word2 && !word3 && !strcmp("--help", word1))
            print_help();
        else if (!word1 && !word2 && !word3);
        else
            printf("Invalid command\n");

        printf(ANSI_COLOR_GREEN "sniff-dmn> " ANSI_COLOR_RESET);
    }
    exit(EXIT_SUCCESS);
}


int request_to_daemon(const char *msg)
{
    int socket_fd;
    struct sockaddr_un name;
    /* Create the socket.  */
    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    /* Store the server’s name in the socket address.  */
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, SOCKET_NAME);
    /* Connect the socket.  */
    int status = connect(socket_fd, (struct sockaddr *)&name, SUN_LEN (&name));

    char buff[BUFF_SIZE];
	strcpy(buff, msg);

	write(socket_fd, buff, BUFF_SIZE);

	if (status == 0)
	{
        while(1)
        {
            read(socket_fd, buff, BUFF_SIZE);
            if (!strcmp(buff, "end"))
                break;
            printf("%s\n", buff);
        }
        close(socket_fd);
        return 1;
	}
    else
    {
        return 0;
        close(socket_fd);
    }
}

void start_sniffer_dmn(unsigned int iface)
{
    /* Process ID and Session ID */
    pid_t pid, sid;
    int pidFilehandle;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        return;

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
        exit(EXIT_FAILURE);

    // /* Change the current working directory */
    set_work_dir();

    pidFilehandle = open(PID_FILE, O_RDWR|O_CREAT, 0600);

    if (pidFilehandle == -1 )
    {
        /* Couldn't open lock file */
        exit(EXIT_FAILURE);
    }

    /* Try to lock file */
    if (lockf(pidFilehandle, F_TLOCK, 0) == -1)
    {
        /* Couldn't get lock on lock file */
        exit(EXIT_FAILURE);
    }

    /* Get and format PID */
    char str[10];
    sprintf(str, "%d\n", getpid());

    /* write pid to lockfile */
    write(pidFilehandle, str, strlen(str));

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    sniffer(iface);

    exit(EXIT_SUCCESS);
}

void set_work_dir(void)
{
    struct stat st;
    if (stat(DAEMON_DIR, &st) == -1)
        mkdir(DAEMON_DIR, 0777);

    if ((chdir(DAEMON_DIR)) < 0)
        exit(EXIT_FAILURE);
}

void print_help(void)
{
    printf("Commands:\n\n");
    printf("   start\t\tstart sniffing from from default iface(eth0)\n");
    printf("   stop\t\t\tstop sniffing packets\n");
    printf("   show [ip] count\tprint number of packets recieved from ip address\n");
    printf("   select iface [iface]\tselect interface for sniffing\n");
    printf("   stat [iface]\t\tshow statistics for particular interface,if iface ommited - for all ifaces\n");
    printf("   iface list\t\tshow interface list\n");
    printf("   quit, q\t\texit sniff-dmn\n");
    printf("   --help\t\tshow usage information\n");
}
