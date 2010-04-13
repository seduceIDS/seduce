NAME		= manager

INSTALL		= /usr/bin/install
INSTALL_USER	= root
INSTALL_GROUP	= root
DESTDIR		= /usr/local
BINDIR		= $(DESTDIR)/bin
SYSCONFDIR	= $(DESTDIR)/etc/seduce

INSTALL_PROG_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_PROG	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 640

CC		= gcc
LD		= ld
TIER_ARCH	= THREE
#TIER_ARCH	= TWO
DEBUG		= -g -D_DEBUG
RELEASE		= -O2
CFLAGS		= -D_BSD_SOURCE -Wall $(DEBUG)
LDFLAGS		= 
LIBS_CFLAGS	= `pkg-config --cflags glib-2.0`
LIBS		= `pkg-config --libs glib-2.0` \
		  `libprelude-config --libs` \
		  -lpthread -lm -lconfuse

OBJS		= manager.o sensor_contact.o data.o hash.o alert.o utils.o \
		  agent_contact.o thread.o options.o oom_handler.o alert_recv.o

HEADERS		= data.h sensor_contact.h agent_contact.h hash.h errors.h \
		  alert.h utils.h thread.h oom_handler.h alert_recv.h options.h

ifeq ($(TIER_ARCH), TWO)
	CFLAGS += -DTWO_TIER_ARCH
endif

.PHONY: all two-tier-arch clean install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

ifeq ($(TIER_ARCH), TWO)
all: $(NAME)_comp.o
else
all: $(NAME)
endif

two-tier-arch:
	$(MAKE) TIER_ARCH=TWO

$(NAME): $(OBJS) $(HEADERS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(NAME)_comp.o: $(OBJS) $(HEADERS)
	$(LD) -r $(OBJS) -o $@

clean:
	rm -f *.o *~ a.out $(NAME) $(NAME)_comp.o

install: install-bin install-conf
	@echo $(NAME) installation completed

install-bin: $(NAME)
	@echo Installing binaries under $(BINDIR) ...
#	$(INSTALL_PROG_DIR) $(BINDIR)
	$(INSTALL_PROG) $(NAME) $(BINDIR)

install-conf:
	@echo Installing configuration files under $(SYSCONFDIR)
	-$(INSTALL_CONF_DIR) $(SYSCONFDIR)
	$(INSTALL_CONF) $(NAME).conf $(SYSCONFDIR)

#EOF
