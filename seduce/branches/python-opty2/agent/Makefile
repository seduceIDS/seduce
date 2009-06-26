#
# Makefile for 'agent' (and the 'seduce' utility)
#

AVAIL_ENGINES 	= qemu libemu fnord dummy
ENGINE		= dummy

# libemu has a bug when registering the library dir to pkg-config
# for now, specify the location of the libemu library
# we'll unset this once the bug is fixed
LIBEMU_LIB_BUG = -L/opt/libemu/lib/libemu

INSTALL_USER	= root
INSTALL_GROUP	= root
DESTDIR		= /usr/local
BINDIR		= $(DESTDIR)/bin
SYSCONFDIR	= $(DESTDIR)/etc/seduce

INSTALL		= /usr/bin/install
INSTALL_PROG_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_PROG	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 640

PKG_CONFIG	= /usr/bin/pkg-config

CC		= gcc
# DEBUG		= -ggdb -D_DEBUG -D_NO_MIN_BLOCK_LENGTH
DEBUG		= -ggdb -D_DEBUG 
# Make this -O0 for easier debugging.
OPT		= -O2
CFLAGS		= -Wall -D_GNU_SOURCE $(OPT) $(DEBUG)
LDFLAGS		= -lconfuse

CFLAGS_QEMU	= -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/ -I../sensor/ -I./
LDFLAGS_QEMU	= -lqemu

ifeq ($(ENGINE), libemu)
CFLAGS_LIBEMU	:= $(shell ${PKG_CONFIG} libemu --cflags)
LDFLAGS_LIBEMU	:= $(LIBEMU_LIB_BUG) $(shell ${PKG_CONFIG} libemu --libs)
endif

AGENT_OBJS	= agent.o detect_engine.o sensor_contact.o item_selection.o error.o alert.o options.o base64_encoder.o md5.o utils.o

SEDUCE_OBJS	= seduce.o detect_engine.o

ifeq ($(ENGINE), qemu)
	CFLAGS += $(CFLAGS_QEMU)
	LDFLAGS += $(LDFLAGS_QEMU)
	AGENT_OBJS += detect_engine_qemu.o
	SEDUCE_OBJS += detect_engine_qemu.o
endif

ifeq ($(ENGINE), libemu)
	CFLAGS += $(CFLAGS_LIBEMU)
	LDFLAGS += $(LDFLAGS_LIBEMU)
	AGENT_OBJS += detect_engine_libemu.o
	SEDUCE_OBJS += detect_engine_libemu.o
endif

ifeq ($(ENGINE), fnord)
	AGENT_OBJS += detect_engine_fnord.o
	SEDUCE_OBJS += detect_engine_fnord.o
endif

ifeq ($(ENGINE), dummy)
	AGENT_OBJS += detect_engine_dummy.o
	SEDUCE_OBJS += detect_engine_dummy.o
endif

.PHONY: all dummy qemu libemu fnord clean install install-bin install-conf help

all: agent seduce

dummy:
	$(MAKE) ENGINE=dummy

qemu:
	$(MAKE) ENGINE=qemu

libemu:
	$(MAKE) ENGINE=libemu

fnord:
	$(MAKE)	ENGINE=fnord

agent: $(AGENT_OBJS) 
	$(CC) -o $@ $(AGENT_OBJS) $(LDFLAGS)
	@echo
	@echo [agent] built against [$(ENGINE)] detection engine.
	@echo

seduce: $(SEDUCE_OBJS)
	$(CC) -o $@ $(SEDUCE_OBJS) $(LDFLAGS)
	@echo
	@echo [seduce] built against [$(ENGINE)] detection engine.
	@echo

agent.o: agent.c alert.h error.h options.h detect_engine.h sensor_contact.h item_selection.h utils.h
	$(CC) $(CFLAGS) -c agent.c

seduce.o: seduce.c detect_engine.h
	$(CC) $(CFLAGS) -c seduce.c

alert.o: alert.c base64_encoder.h utils.h sensor_contact.h detect_engine.h
	$(CC) $(CFLAGS) -c alert.c

detect_engine.o: detect_engine.c detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine.c 

options.o: options.c options.h item_selection.h
	$(CC) $(CFLAGS) -c options.c

sensor_contact.o: sensor_contact.c sensor_contact.h error.h utils.h
	$(CC) $(CFLAGS) -c sensor_contact.c

item_selection.o: item_selection.c item_selection.h 
	$(CC) $(CFLAGS) -c item_selection.c

error.o: error.c error.h
	$(CC) $(CFLAGS) -c error.c

base64_encoder.o: base64_encoder.c base64_encoder.h
	$(CC) $(CFLAGS) -c base64_encoder.c

detect_engine_qemu.o: detect_engine_qemu.c utils.h detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine_qemu.c 

detect_engine_libemu.o: detect_engine_libemu.c utils.h detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine_libemu.c

detect_engine_fnord.o: detect_engine_fnord.c utils.h detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine_fnord.c

detect_engine_dummy.o: detect_engine_dummy.c utils.h
	$(CC) $(CFLAGS) -c detect_engine_dummy.c 

utils.o: utils.c utils.h md5.h
	$(CC) $(CFLAGS) -c utils.c

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c md5.c

clean:
	@rm -f *.o *~ agent seduce 

install: install-bin install-conf
	@echo $(NAME) installation completed

install-bin: $(NAME)
	@echo Installing binaries under $(BINDIR) ...
	-$(INSTALL_PROG_DIR) $(BINDIR)
	$(INSTALL_PROG) $(NAME) $(BINDIR)

install-conf:
	@echo Installing configuration files under $(SYSCONFDIR)
	-$(INSTALL_CONF_DIR) $(SYSCONFDIR)
	$(INSTALL_CONF) $(NAME).conf $(SYSCONFDIR)

help:
	@echo
	@echo Type \'make\' to build both the \'agent\' \& \'seduce\' utility
	@echo using the default detection engine \($(ENGINE)\).
	@echo
	@echo To build against a different engine you can specify the engine
	@echo name either as a make target or as the value of the make variable
	@echo ENGINE, like this:
	@echo 
	@echo make qemu
	@echo or
	@echo make agent ENGINE=qemu
	@echo
	@echo Available detection engines are: $(AVAIL_ENGINES)
	@echo
# EOF
