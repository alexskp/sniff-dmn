
EXEC = sniff-dmn

CC = gcc

CFLAGS = -g -c -Wall -Werror -Wextra

SRCDIR = src

SRC = main.c \
		sniffer.c \
		cli.c \
		tools.c \
		bst.c \
		bst_list.c \
		bst_file.c \
		list.c

OBJ = $(addprefix $(SRCDIR)/, $(SRC:.c=.o))

.PHONY: all
all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $(EXEC) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<


.PHONY: clean
clean:
	rm -f $(OBJ)

.PHONY: fclean
fclean:
	rm -f $(OBJ)
	rm -f $(EXEC)

.PHONY: re
re: fclean all
