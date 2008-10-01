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

PCAP_CFLAGS	= 
PCAPLIB		= -lpcap

LIBS_CFLAGS	= $(PCAP_CFLAGS)
LIBS		= -lnids $(PCAPLIB) -lgthread-2.0 -lnsl -lconfuse

OBGS		= sensor.o chksum_ctl.o server_contact.o options.o
HDRS		= sensor.h server_contact.h


.PHONY: all clean install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: $(NAME)

$(NAME):$(OBGS) $(HDRS)
	$(CC) -o $@  $(OBGS) $(LDFLAGS) $(LIBS)

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
