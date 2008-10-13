NAME		= sensor

INSTALL		= /usr/bin/install
INSTALL_USER	= root
INSTALL_GROUP	= root
DESTDIR		= /usr/local
BINDIR		= $(DESTDIR)/sbin
SYSCONFDIR	= $(DESTDIR)/etc/seduce

INSTALL_PROG_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_PROG	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF_DIR= $(INSTALL) -d -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755
INSTALL_CONF	= $(INSTALL) -c -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 640

CC		= gcc
DEBUG		= -g -D_DEBUG
RELEASE		= -O2
CFLAGS		= -D_BSD_SOURCE -Wall $(DEBUG)

GLIB_CFLAGS	= `pkg-config --cflags glib-2.0`
GLIB		= `pkg-config --libs glib-2.0`

NIDS_CFLAGS	=
NIDS		= -lnids -lpcap -lgthread-2.0 -lnsl

CONFUSE_CFLAGS	=
CONFUSE		= -lconfuse

PRELUDE_CFLAGS	= `libprelude-config --cflags`
PRELUDE		= `libprelude-config --libs`

LIBS_CFLAGS	= $(GLIB_CFLAGS) $(NIDS_CFLAGS) $(CONFUSE_CFLAGS) \
		  $(PRELUDE_CFLAGS)
LIBS		= $(GLIB) $(NIDS) $(CONFUSE) $(PRELUDE) -lm

OBJS		= sensor.o chksum_ctl.o data.o hash.o sensor_contact.o \
		  sniffer.o options.o thread.o utils.o oom_handler.o \
		  agent_contact.o alert.o alert_recv.o

HDRS		= sensor.h data.h hash.h sensor_contact.h options.h sniffer.h \
		  thread.h utils.h errors.h oom_handler.h agent_contact.h \
		  alert.h alert_recv.h


.PHONY: all clean install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: $(NAME)

$(NAME): $(OBJS) $(HDRS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o *~ sensor

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
