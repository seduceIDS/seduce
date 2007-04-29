#
# Makefile for libnids samples.
#

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_BSD_SOURCE -D_DEBUG -Wall
LDFLAGS		= 

PCAP_CFLAGS	= 
PCAPLIB		= -lpcap

LNET_CFLAGS	= 
LNETLIB		= 

LIBS_CFLAGS	= $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS		= -lnids $(PCAPLIB) $(LNETLIB) -lgthread-2.0 -lnsl 

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: sensor
static shared: all

sensor: sensor.o chksum_ctl.o server_contact.o server_contact.h
	$(CC) -o $@ sensor.o chksum_ctl.o server_contact.o $(LDFLAGS) $(LIBS)


clean:
	rm -f *.o *~ sensor

# EOF
