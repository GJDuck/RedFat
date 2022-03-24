#!/bin/bash
#
# Copyright (C) 2022 National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

if [ ! -x ../redfat.bin ]
then
    echo -e "${RED}error${OFF}: build RedFat first"
    exit 1
fi

set -x

LD_PRELOAD=$PWD/../libredfat.so gcc -O2 -o test test.c
LD_PRELOAD=$PWD/../libredfat.so ../redfat.bin -Xreads ./test
LD_PRELOAD=$PWD/../libredfat.so ./test.redfat 

