#!/bin/sh

git submodule update --init
# libemu v1.0.3 build breaks due to a warning
sed -i 's/ -Werror//' agent/libemu/src/Makefile.am
aclocal
autoheader
automake --add-missing
autoconf
