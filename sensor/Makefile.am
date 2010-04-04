AM_CFLAGS = -Wall -O2 -ggdb -D_DEBUG -D_BSD_SOURCE -DCONF_DIR="${sysconfdir}"

sbin_PROGRAMS = seduce-sensor
sysconf_DATA = sensor.conf

seduce_sensor_SOURCES = agent_contact.c alert.c alert_recv.c chksum_ctl.c \
          data.c hash.c oom_handler.c options.c sensor.c sensor_contact.c \
          signal_waiter.c sniffer.c thread.c utils.c

seduce_sensor_LDADD = @GLIB_LIBS@ @LIBCONFUSE_LIBS@ @LIBNIDS_LIBS@ \
	@LIBPTHREAD_LIBS@ @LIBM_LIBS@ @LIBPRELUDE_LIBS@

seduce_sensor_CFLAGS = $(AM_CFLAGS) @GLIB_CFLAGS@ @LIBCONFUSE_CFLAGS@ \
	@LIBPRELUDE_CFLAGS@

install-exec-hook:
	chown root:root $(DESTDIR)$(sbindir)/seduce-sensor
	chmod 0700 $(DESTDIR)$(sbindir)/seduce-sensor
	chown root:root $(DESTDIR)$(sysconfdir)/sensor.conf
	chmod 0600 $(DESTDIR)$(sysconfdir)/sensor.conf
