#
# Makefile for the agent
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_DEBUG -Wall -D_GNU_SOURCE -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/ -I../sensor/
LDFLAGS		= 

LIBS_CFLAGS	= 
LIBS		= -lconfuse -lqemu

all: agent seduce

agent: agent.o detect_engine.o alert.o options.o
	$(CC) -o $@ agent.o detect_engine.o alert.o options.o $(LDFLAGS) $(LIBS)

seduce: seduce.o detect_engine.o
	$(CC) -o $@ seduce.o detect_engine.o -lqemu

seduce.o: seduce.c
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) seduce.c

agent.o: agent.c agent.h detect_engine.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) agent.c

alert.o: alert.c agent.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) detect_engine.c

options.o: options.c agent.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) options.c



clean:
	rm -f *.o *~ agent seduce

# EOF
