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
CFLAGS		= -g -O2 -D_BSD_SOURCE -Wall -D_DEBUG
LDFLAGS		= 
LIBS_CFLAGS	= `pkg-config --cflags glib-2.0`
LIBS		= `pkg-config --libs glib-2.0` \
		  `libprelude-config --libs` \
		  -lpthread -lm -lconfuse

OBJS		= manager.o sensor_contact.o data.o hash.o job.o \
		  alert.o utils.o agent_contact.o thread.o options.o \
		  oom_handler.o alert_recv.o

HEADERS		= data.h sensor_contact.h agent_contact.h hash.h errors.h \
		  job.h alert.h utils.h thread.h oom_handler.h alert_recv.h

.PHONY: all clean install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: manager

manager: $(OBJS) $(HEADERS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o *~ manager

install: install-bin install-conf
	@echo $(NAME) installation completed

install-bin:
	@echo Installing binaries under $(BINDIR) ...
#	$(INSTALL_PROG_DIR) $(BINDIR)
	$(INSTALL_PROG) $(NAME) $(BINDIR)

install-conf:
	@echo Installing configuration files under $(SYSCONFDIR)
	-$(INSTALL_CONF_DIR) $(SYSCONFDIR)
	$(INSTALL_CONF) $(NAME).conf $(SYSCONFDIR)

#EOF
