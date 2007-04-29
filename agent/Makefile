#
# Makefile for libnids samples.
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_DEBUG -Wall
LDFLAGS		= 

LIBS_CFLAGS	= 
LIBS		= 

all: agent

agent: agent.o detect_engine.o alert.o
	$(CC) -o $@ agent.o detect_engine.o alert.o $(LDFLAGS) $(LIBS)

agent.o: agent.c agent.h detect_engine.h config.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) agent.c

alert.o: alert.c alert.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) detect_engine.c



clean:
	rm -f *.o *~ agent

# EOF
