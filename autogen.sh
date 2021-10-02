#!/bin/sh

git submodule update --init
aclocal
autoheader
automake --add-missing
autoconf
