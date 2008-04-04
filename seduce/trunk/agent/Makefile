#
# Makefile for the agent
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_DEBUG -Wall -D_GNU_SOURCE
CFLAGS_QEMU	= -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/ -I../sensor/
LDFLAGS		= 

LIBS_CFLAGS	= 

LIBS_AGENT	= -lconfuse
LIBS_QEMU	= -lqemu
LIBS		= $(LIBS_AGENT) $(LIBS_QEMU)

CORE_OBJS	= server_contact.o error.o alert.o options.o utils.o

all: agent seduce 

dummy:	dummy_agent
dummy_agent: CFLAGS += -D_DUMMY_ENGINE
dummy_agent: agent.o detect_engine.o dummy_detect_engine.o $(CORE_OBJS)
	$(CC) -o $@ agent.o detect_engine.o dummy_detect_engine.o $(CORE_OBJS) $(LDFLAGS) $(LIBS_AGENT)

agent: CFLAGS += $(CFLAGS_QEMU)
agent: agent.o detect_engine.o qemu_detect_engine.o $(CORE_OBJS)
	$(CC) -o $@ agent.o detect_engine.o qemu_detect_engine.o $(CORE_OBJS) $(LDFLAGS) $(LIBS)

seduce: CFLAGS += $(CFLAGS_QEMU)
seduce: seduce.o detect_engine.o qemu_detect_engine.o
	$(CC) -o $@ seduce.o detect_engine.o qemu_detect_engine.o $(LIBS_QEMU)

seduce.o: seduce.c
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) seduce.c

alert.o: alert.c agent.h
	$(CC) $(CFLAGS) -c alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine.c 

options.o: options.c agent.h
	$(CC) $(CFLAGS) -c options.c

server_contact.o: server_contact.c server_contact.h error.h utils.h
	$(CC) $(CFLAGS) -c server_contact.c

utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c

error.o: error.c error.h
	$(CC) $(CFLAGS) -c error.c

qemu_detect_engine.o: qemu_detect_engine.c qemu_detect_engine.h
	$(CC) $(CFLAGS) -c qemu_detect_engine.c 

dummy_detect_engine.o: dummy_detect_engine.c
	$(CC) $(CFLAGS) -c dummy_detect_engine.c 

clean:
	rm -f *.o *~ agent seduce dummy_agent

# EOF
