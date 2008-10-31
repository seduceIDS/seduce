#
# Makefile for the agent
#

NAME		= agent

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
DEBUG		= -ggdb -D_DEBUG
OPT		= -O2
CFLAGS		= -Wall -D_GNU_SOURCE $(OPT) $(DEBUG)
LDFLAGS		= -lconfuse

CFLAGS_QEMU	= -Ilibqemu-0.9.0/ -Ilibqemu-0.9.0/linux-user/ -Ilibqemu-0.9.0/target-i386/ -Ilibqemu-0.9.0/i386-linux-user/ -Ilibqemu-0.9.0/fpu/ -Ilibqemu-0.9.0/linux-user/i386/ -I../sensor/ -I./
LDFLAGS_QEMU	= -lqemu

CFLAGS_LIBEMU	:= $(shell ${PKG_CONFIG} libemu --cflags)
LDFLAGS_LIBEMU	:= $(LIBEMU_LIB_BUG) $(shell ${PKG_CONFIG} libemu --libs)

CORE_OBJS	= agent.o detect_engine.o sensor_contact.o item_selection.o error.o alert.o options.o base64_encoder.o md5.o utils.o

ifeq ($(ENGINE), qemu)
	CFLAGS += $(CFLAGS_QEMU)
	LDFLAGS += $(LDFLAGS_QEMU)
	OBJS = $(CORE_OBJS) detect_engine_qemu.o
endif

ifeq ($(ENGINE), libemu)
	CFLAGS += $(CFLAGS_LIBEMU)
	LDFLAGS += $(LDFLAGS_LIBEMU)
	OBJS = $(CORE_OBJS) detect_engine_libemu.o
endif

ifeq ($(ENGINE), dummy)
	OBJS = $(CORE_OBJS) detect_engine_dummy.o
endif

.PHONY: all dummy qemu clean install install-bin install-conf

all: $(NAME) 

dummy:
	$(MAKE) ENGINE=dummy

qemu:
	$(MAKE) ENGINE=qemu

libemu:
	$(MAKE) ENGINE=libemu

$(NAME): $(OBJS) 
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	@echo
	@echo The agent is linked against the '*'$(ENGINE)'*' detection engine. 
	@echo If you want to use another engine, either modify the ENGINE 
	@echo variable or use the engine name as a target like this":"
	@echo
	@echo -e "\t make qemu"
	@echo -e "\t make libemu"
	@echo -e "\t make dummy"
	@echo

seduce: seduce.c detect_engine.o detect_engine_qemu.o
	$(CC) $(CFLAGS) $(CFLAGS_QEMU) -o $@ $^ $(LDFLAGS_QEMU)

agent.o: agent.c alert.h error.h options.h detect_engine.h sensor_contact.h item_selection.h utils.h
	$(CC) $(CFLAGS) -c agent.c

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

detect_engine_qemu.o: detect_engine_qemu.c detect_engine_qemu.h utils.h detect_engine.h
	$(CC) $(CFLAGS) -c detect_engine_qemu.c 

detect_engine_libemu.o: detect_engine_libemu.c detect_engine_libemu.h detect_engine.h utils.h
	$(CC) $(CFLAGS) -c detect_engine_libemu.c

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

# EOF
