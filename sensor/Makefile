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
LDFLAGS		= 

AR		= ar
RANLIB		= ranlib

PCAP_CFLAGS	= 
PCAPLIB		= -lpcap

LIBS_CFLAGS	= $(PCAP_CFLAGS)
LIBS		= -lnids $(PCAPLIB) -lgthread-2.0 -lnsl -lconfuse

OBJS		= sensor.o chksum_ctl.o libseduce_sensor.a options.o
HDRS		= sensor.h server_contact.h


.PHONY: all libs clean install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: libs $(NAME)

$(NAME):$(OBJS) $(HDRS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

libs: libseduce_sensor.a libseduce_sensor.so

# during installation time this must be named libseduce_sensor.so.1
libseduce_sensor.so: server_contact_pic.o
	$(CC) -shared -Wl,-soname,libseduce_sensor.so.1 -o libseduce_sensor.so $^

server_contact_pic.o: server_contact.c server_contact.h
	$(CC) -o $@ -c $(CFLAGS) -fPIC -I. server_contact.c

libseduce_sensor.a: server_contact.o
	$(AR) crv $@ $^
	$(RANLIB) $@

clean:
	rm -f *.o *.a *.so *~ sensor

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
