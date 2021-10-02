#!/bin/sh

git submodule update --init
# libemu v1.0.4 build breaks due to a warning
cd agent
sed -i 's/ -Werror//' libemu/src/Makefile.am
patch -p2 < libemu_shellcode.patch
cd ..
aclocal
autoheader
automake --add-missing
autoconf
cd agent/libemu && autoreconf -v -i
