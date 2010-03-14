#!/bin/sh

./configure --enable-linux-user --disable-system --disable-kqemu --target-list=i386-linux-user --disable-sdl $@
