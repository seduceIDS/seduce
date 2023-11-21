AM_CFLAGS = -Wall -O2 -D_GNU_SOURCE -DCONF_DIR="\"${sysconfdir}\""

# this disables the MINIMUM block length check of the detection engines
# AM_CFLAGS += -D_NO_MIN_BLOCK_LENGTH

# this disables splitting input blocks whenever a NUL character is encountered
AM_CFLAGS += -D_NO_SPLIT_AT_NUL

# debugging stuff
# AM_CFLAGS += -ggdb -D_DEBUG

bin_PROGRAMS = seduce-agent seduce
sysconf_DATA = agent.conf

libexec_PROGRAMS =
SUBDIRS =
DETECTION_ENGINES =

if HAVE_QEMU
DETECTION_ENGINES += detection_engine_qemu.c
SUBDIRS += qemu-0.12.4
endif

if HAVE_LINUX_X86_64
DETECTION_ENGINES += detection_engine_unicorn_linux_x86_64.c
SUBDIRS += unicorn
endif

if HAVE_WINDOWS_X86
DETECTION_ENGINES += detection_engine_unicorn_windows_x86.c
dlldir = $(pkgdatadir)/DLL/windows-x86/system32
dll_DATA = ./DLL/windows-x86/system32/kernel32.dll
AM_CFLAGS += -DDLL_DIR="\"${dlldir}\""
SUBDIRS += unicorn readpe
endif

if HAVE_LIBEMU
DETECTION_ENGINES += detection_engine_libemu.c
SUBDIRS += libemu
endif

if HAVE_YARA
DETECTION_ENGINES += detection_engine_yara.c
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
seduce_agent_DEPENDENCIES = @UNICORN_STATIC_LIB@ @LIBEMU_STATIC_LIB@ @LIBPE_STATIC_LIB@
seduce_agent_CFLAGS = $(AM_CFLAGS) @UNICORN_CFLAGS@ @QEMU_CFLAGS@ @LIBEMU_CFLAGS@ \
			@LIBPYTHON_CFLAGS@ @LIBCONFUSE_CFLAGS@ @LIBPE_CFLAGS@
seduce_agent_LDADD = @LIBYARA_LIBS@ @QEMU_LIBS@ @UNICORN_LIBS@ @LIBEMU_LIBS@ @LIBPYTHON_LIBS@ @LIBCONFUSE_LIBS@ @LIBPE_LIBS@

seduce_SOURCES = standalone.c utils.c md5.c detection_engine.c $(DETECTION_ENGINES)
seduce_DEPENDENCIES = @UNICORN_STATIC_LIB@ @LIBEMU_STATIC_LIB@ @LIBPE_STATIC_LIB@
seduce_CFLAGS = $(AM_CFLAGS) @UNICORN_CFLAGS@ @QEMU_CFLAGS@ @LIBEMU_CFLAGS@ @LIBPYTHON_CFLAGS@ @LIBPE_CFLAGS@
seduce_LDADD = @LIBYARA_LIBS@ @QEMU_LIBS@ @UNICORN_LIBS@ @LIBEMU_LIBS@ @LIBPYTHON_LIBS@ @LIBPE_LIBS@

# do not recurse further for installation
install installdirs: SUBDIRS =

install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/seduce-agent
	chmod 0700 $(DESTDIR)$(bindir)/seduce-agent
	chown root:root	$(DESTDIR)$(bindir)/seduce
	chmod 0755 $(DESTDIR)$(bindir)/seduce
	chown root:root $(DESTDIR)$(sysconfdir)/agent.conf
	chmod 0600 $(DESTDIR)$(sysconfdir)/agent.conf

