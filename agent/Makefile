#
# Makefile for the agent
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_DEBUG -Wall
LDFLAGS		= 

LIBS_CFLAGS	= 
LIBS		= -lconfuse

all: agent

agent: agent.o detect_engine.o alert.o options.o
	$(CC) -o $@ agent.o detect_engine.o alert.o options.o $(LDFLAGS) $(LIBS)

agent.o: agent.c agent.h detect_engine.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) agent.c

alert.o: alert.c agent.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) detect_engine.c

options.o: options.c agent.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) options.c



clean:
	rm -f *.o *~ agent

# EOF
