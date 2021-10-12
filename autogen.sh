#!/bin/sh

git submodule update --init
aclocal
autoheader
automake --add-missing
autoconf
cd agent/libemu && autoreconf -v -i
