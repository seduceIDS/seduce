CC		= gcc
CFLAGS		= -g -O2 -D_BSD_SOURCE -Wall -D_DEBUG
LDFLAGS		= 
LIBS_CFLAGS	= `pkg-config --cflags glib-2.0`
LIBS		= `pkg-config --libs glib-2.0` \
		  `libprelude-config --libs` \
		  -lpthread -lm -lconfuse

OBJS		= manager.o sensor_contact.o data.o hash.o job.o \
		  alert.o utils.o agent_contact.o thread.o options.o \
		  oom_handler.o

HEADERS		= data.h sensor_contact.h agent_contact.h hash.h errors.h \
		  job.h alert.h utils.h thread.h oom_handler.h
.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: manager

manager: $(OBJS) $(HEADERS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o *~ manager
