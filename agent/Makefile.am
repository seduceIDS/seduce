AM_CFLAGS = -Wall -O2 -ggdb -D_DEBUG -D_GNU_SOURCE -DCONF_DIR="${sysconfdir}"
# this disables the MINIMUM block length check of the detection engines
# AM_CFLAGS += -D_NO_MIN_BLOCK_LENGTH

# reset LIBS, because it will append automatically all libs discovered by
# AC_SEARCH_LIBS (see ../configure.ac)
LIBS=

bin_PROGRAMS = seduce-agent seduce
sysconf_DATA = agent.conf

DETECTION_ENGINES =

if HAVE_QEMU
DETECTION_ENGINES += detection_engine_qemu.c
endif

if HAVE_LIBEMU
DETECTION_ENGINES += detection_engine_libemu.c
# libemu registers the wrong libdir to PKG_CONFIG.
# remove this, once the bug is gone!
LIBEMU_LIBS += -L/opt/libemu/lib/libemu/
endif

if HAVE_DUMMY
DETECTION_ENGINES += detection_engine_dummy.c
endif

if HAVE_FNORD
DETECTION_ENGINES += detection_engine_fnord.c
endif

seduce_agent_SOURCES = agent.c alert.c base64.c detection_engine.c error.c \
			item_selection.c manager_protocol.c md5.c options.c \
			utils.c worker.c $(DETECTION_ENGINES)
seduce_agent_CFLAGS = $(AM_CFLAGS) @QEMU_CFLAGS@ @LIBEMU_CFLAGS@ \
			@LIBCONFUSE_CFLAGS@
seduce_agent_LDADD = $(AM_LDFLAGS) @QEMU_LIBS@ $(LIBEMU_LIBS) \
			@LIBCONFUSE_LIBS@

seduce_SOURCES = standalone.c detection_engine.c $(DETECTION_ENGINES)
seduce_CFLAGS = $(AM_CFLAGS) @QEMU_CFLAGS@ @LIBEMU_CFLAGS@
seduce_LDADD = $(AM_LDFLAGS) @QEMU_LIBS@ $(LIBEMU_LIBS)

install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/seduce-agent
	chmod 0700 $(DESTDIR)$(bindir)/seduce-agent
	chown root:root	$(DESTDIR)$(bindir)/seduce
	chmod 0755 $(DESTDIR)$(bindir)/seduce
	chown root:root $(DESTDIR)$(sysconfdir)/agent.conf
	chmod 0600 $(DESTDIR)$(sysconfdir)/agent.conf
