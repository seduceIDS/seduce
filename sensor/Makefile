
CC		= gcc
CFLAGS		= -g -O2 -D_BSD_SOURCE -D_DEBUG -Wall
LDFLAGS		= 

PCAP_CFLAGS	= 
PCAPLIB		= -lpcap

LIBS_CFLAGS	= $(PCAP_CFLAGS)
LIBS		= -lnids $(PCAPLIB) -lgthread-2.0 -lnsl -lconfuse

OBGS		= sensor.o chksum_ctl.o server_contact.o options.o
HDRS		= sensor.h server_contact.h

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: sensor
static shared: all

sensor: $(OBGS) $(HDRS)
	$(CC) -o $@  $(OBGS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ sensor

# EOF
