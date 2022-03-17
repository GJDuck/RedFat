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

# Self-harden RedFat
set -e
cd install
./redfat.bin -force -Xallowlist-gen ./redfat.bin
./redfat.bin -force -Xallowlist-gen ./e9patch
./redfat.bin -force -Xallowlist-gen ./e9tool
./redfat.bin -Xallowlist-gen ./RedFatPlugin.so
rm ./e9patch ./e9tool ./RedFatPlugin.so
mv ./redfat.bin ./redfat.bin.orig
ln -f -s ./redfat.bin.gen ./redfat.bin
ln -f -s ./e9patch.gen ./e9patch
ln -f -s ./e9tool.gen ./e9tool
ln -f -s ./RedFatPlugin.so.gen ./RedFatPlugin.so
LD_PRELOAD=$PWD/libredfat.so ./redfat.bin -force ../E9PATCH/e9patch \
    -o /dev/null
rm ./redfat.bin ./e9patch ./e9tool ./RedFatPlugin.so
rm ./redfat.bin.gen ./e9patch.gen ./e9tool.gen ./RedFatPlugin.so.gen
ln -f -s ../E9PATCH/e9patch
ln -f -s ../E9PATCH/e9tool
ln -f -s ../RedFatPlugin.so
mv ./redfat.bin.orig ./redfat.bin
LD_PRELOAD=$PWD/libredfat.so ./redfat.bin -force \
    -Xallowlist-use -Xallowlist-mode=RL-R ./redfat.bin
LD_PRELOAD=$PWD/libredfat.so ./redfat.bin -force \
    -Xallowlist-use -Xallowlist-mode=RL-R ./e9patch
LD_PRELOAD=$PWD/libredfat.so ./redfat.bin -force \
    -Xallowlist-use -Xallowlist-mode=RL-R ./e9tool
LD_PRELOAD=$PWD/libredfat.so ./redfat.bin \
    -Xallowlist-use -Xallowlist-mode=RL-R ./RedFatPlugin.so
rm ./redfat.bin.allow ./e9patch.allow ./e9tool.allow ./RedFatPlugin.so.allow
mv ./redfat.bin.redfat ./redfat.bin
mv ./e9patch.redfat ./e9patch
mv ./e9tool.redfat ./e9tool
mv ./RedFatPlugin.so.redfat ./RedFatPlugin.so

echo -e "${GREEN}$0${OFF}: done!"

