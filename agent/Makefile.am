AM_CFLAGS = -Wall -O2 -D_GNU_SOURCE -DCONF_DIR="${sysconfdir}"

# this disables the MINIMUM block length check of the detection engines
# AM_CFLAGS += -D_NO_MIN_BLOCK_LENGTH

# this disables splitting input blocks whenever a NUL character is encountered
AM_CFLAGS += -D_NO_SPLIT_AT_NUL

# debugging stuff
# AM_CFLAGS += -ggdb -D_DEBUG

bin_PROGRAMS = seduce-agent seduce
sysconf_DATA = agent.conf

DETECTION_ENGINES =

if HAVE_QEMU
DETECTION_ENGINES += detection_engine_qemu.c
endif

if HAVE_UNICORN
DETECTION_ENGINES += detection_engine_unicorn_x86_64.c
endif

if HAVE_LIBEMU
DETECTION_ENGINES += detection_engine_libemu.c
endif

if HAVE_DUMMY
DETECTION_ENGINES += detection_engine_dummy.c
endif

if HAVE_FNORD
DETECTION_ENGINES += detection_engine_fnord.c
endif

if HAVE_PYOPTY2
DETECTION_ENGINES += detection_engine_pyopty2.c
python_PYTHON = detection_engine_pyopty2.py
endif

seduce_agent_SOURCES = agent.c alert.c base64.c detection_engine.c error.c \
			item_selection.c manager_protocol.c md5.c options.c \
			utils.c worker.c $(DETECTION_ENGINES)
seduce_agent_CFLAGS = $(AM_CFLAGS) @UNICORN_CFLAGS@ @QEMU_CFLAGS@ @LIBEMU_CFLAGS@ \
			@LIBPYTHON_CFLAGS@ @LIBCONFUSE_CFLAGS@
seduce_agent_LDADD = @QEMU_LIBS@ @UNICORN_LIBS@ @LIBEMU_LIBS@ @LIBPYTHON_LIBS@ @LIBCONFUSE_LIBS@

seduce_SOURCES = standalone.c detection_engine.c $(DETECTION_ENGINES)
seduce_CFLAGS = $(AM_CFLAGS) @UNICORN_CFLAGS@ @QEMU_CFLAGS@ @LIBEMU_CFLAGS@ @LIBPYTHON_CFLAGS@ 
seduce_LDADD = @QEMU_LIBS@ @UNICORN_LIBS@ @LIBEMU_LIBS@ @LIBPYTHON_LIBS@

install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/seduce-agent
	chmod 0700 $(DESTDIR)$(bindir)/seduce-agent
	chown root:root	$(DESTDIR)$(bindir)/seduce
	chmod 0755 $(DESTDIR)$(bindir)/seduce
	chown root:root $(DESTDIR)$(sysconfdir)/agent.conf
	chmod 0600 $(DESTDIR)$(sysconfdir)/agent.conf
