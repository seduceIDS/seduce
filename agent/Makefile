#
# Makefile for the agent
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_DEBUG -Wall -D_GNU_SOURCE
CFLAGS_QEMU	= -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/ -I../sensor/ -I./

LDFLAGS		= 
LIBS_CFLAGS	= 

LIBS_QEMU	= -lqemu
LIBS		= -lconfuse

CORE_OBJS	= agent.o detect_engine.o server_contact.o error.o alert.o options.o base64_encoder.o

ENGINE		= dummy

ifeq ($(ENGINE), qemu)
	CFLAGS += $(CFLAGS_QEMU)
	LIBS += $(LIBS_QEMU)
	OBJS = $(CORE_OBJS) detect_engine_qemu.o
endif
ifeq ($(ENGINE), dummy)
	OBJS = $(CORE_OBJS) detect_engine_dummy.o
endif

all: agent 
.PHONY: all dummy qemu clean

dummy:
	$(MAKE) ENGINE=dummy

qemu:
	$(MAKE) ENGINE=qemu

agent:	$(OBJS) agent.h server_contact.h alert.h error.h options.h
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)
	@echo
	@echo The agent is linked against the $(ENGINE) detection engine. If you
	@echo want to use another engine, either modify the ENGINE variable or
	@echo use the engine name as a target like this":"
	@echo
	@echo -e "\t make qemu"
	@echo -e "\t make dummy"
	@echo

seduce: seduce.o detect_engine.o detect_engine_qemu.o
	$(CC) -o $@ seduce.o detect_engine.o detect_engine_qemu.o $(LIBS_QEMU)

seduce.o: seduce.c
	$(CC) -c $(CFLAGS) -I.  $(LIBS_CFLAGS) seduce.c

agent.o: agent.c agent.h alert.h error.h options.h detect_engine.h server_contact.h
	$(CC) $(CFLAGS) -c agent.c

alert.o: alert.c agent.h base64_encoder.h
	$(CC) $(CFLAGS) -c alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine.c 

options.o: options.c options.h
	$(CC) $(CFLAGS) -c options.c

server_contact.o: server_contact.c server_contact.h error.h utils.h
	$(CC) $(CFLAGS) -c server_contact.c

error.o: error.c error.h
	$(CC) $(CFLAGS) -c error.c

base64_encoder.o: base64_encoder.c base64_encoder.h
	$(CC) $(CFLAGS) -c base64_encoder.c

detect_engine_qemu.o: detect_engine_qemu.c detect_engine_qemu.h
	$(CC) $(CFLAGS) -c detect_engine_qemu.c 

detect_engine_dummy.o: detect_engine_dummy.c
	$(CC) $(CFLAGS) -c detect_engine_dummy.c 

clean:
	rm -f *.o *~ agent seduce 

# EOF
