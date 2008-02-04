CC     = gcc
CFLAGS = -g -Wall -D_GNU_SOURCE -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/
LIBS   = -lqemu

all: seduce

seduce: seduce.c
	$(CC) $(CFLAGS) $(LIBS) -o $@ seduce.c

clean:
	rm -f seduce

