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

#TIER_ARCH	= THREE
TIER_ARCH	= TWO
LIBS_CFLAGS	= $(PCAP_CFLAGS)
TWO_TIER_CFLAGS	= `pkg-config --cflags glib-2.0`
LIBS		= -lnids $(PCAPLIB) -lgthread-2.0 -lnsl -lconfuse
TWO_TIER_LIBS	= `pkg-config --libs glib-2.0` \
		  `libprelude-config --libs` \
		  -lpthread -lm -lconfuse

OBJS		= sniffer.o sensor.o chksum_ctl.o libseduce_sensor.a options.o
HDRS		= sensor.h sniffer.o server_contact.h

ifeq ($(TIER_ARCH), TWO)
	CFLAGS += -DTWO_TIER_ARCH $(TWO_TIER_CFLAGS)
	LIBS += $(TWO_TIER_LIBS)
endif

.PHONY: all libs two-tier-arch clean clean_manager install install-bin install-conf

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: $(NAME)

two-tier-arch:
	$(MAKE) TIER_ARCH=TWO

ifeq ($(TIER_ARCH), TWO)
$(NAME):$(OBJS) $(HDRS) ../manager/manager_comp.o
	$(CC) -o $@ $(OBJS) ../manager/manager_comp.o $(LDFLAGS) $(LIBS)
else
$(NAME):$(OBJS) $(HDRS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)
endif

libs: libseduce_sensor.a libseduce_sensor.so

../manager/manager_comp.o:
	cd ../manager; $(MAKE) two-tier-arch

# during installation time this must be named libseduce_sensor.so.1
libseduce_sensor.so: server_contact_pic.o
	$(CC) -shared -Wl,-soname,libseduce_sensor.so.1 -o libseduce_sensor.so $^

server_contact_pic.o: server_contact.c server_contact.h
	$(CC) -o $@ -c $(CFLAGS) -fPIC -I. server_contact.c

libseduce_sensor.a: server_contact.o
	$(AR) crv $@ $^
	$(RANLIB) $@

ifeq ($(TIER_ARCH), TWO)
clean: clean_manager
else
clean:
endif
	rm -f *.o *.a *.so *~ a.out sensor

clean_manager:
	cd ../manager; $(MAKE) clean

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
