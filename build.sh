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

E9_VERSION=855e8b8092f27ec5c3deb1bc1e7b28e50da6800f
LIB_VERSION=1c8c703303e6de11b6a6abd67323b5556e25c57f

# STEP (1): install dependencies if necessary:
if [ ! -x e9patch-$E9_VERSION/e9patch ]
then
    if [ ! -f e9patch-$E9_VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading e9patch-$E9_VERSION.zip..."
        wget -O e9patch-$E9_VERSION.zip https://github.com/GJDuck/e9patch/archive/$E9_VERSION.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting e9patch-$E9_VERSION.zip..."
    unzip e9patch-$E9_VERSION.zip

    echo -e "${GREEN}$0${OFF}: building e9patch..."
    cd e9patch-$E9_VERSION
    ./build.sh
    cd ..
    rm -f E9PATCH
    ln -f -s e9patch-$E9_VERSION E9PATCH
    echo -e "${GREEN}$0${OFF}: e9patch has been built..."
else
	echo -e "${GREEN}$0${OFF}: using existing e9patch..."
fi
if [ ! -x libredfat-$LIB_VERSION/libredfat.so ]
then
    if [ ! -f libredfat-$LIB_VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading libredfat-$LIB_VERSION.zip..."
        wget -O libredfat-$LIB_VERSION.zip https://github.com/GJDuck/libredfat/archive/$LIB_VERSION.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting libredfat-$LIB_VERSION.zip..."
    unzip libredfat-$LIB_VERSION.zip

    echo -e "${GREEN}$0${OFF}: building libredfat..."
    (cd libredfat-$LIB_VERSION/; ./build.sh)
    rm -f runtime
    ln -f -s libredfat-$LIB_VERSION runtime
    echo -e "${GREEN}$0${OFF}: libredfat has been built..."
else
    echo -e "${GREEN}$0${OFF}: using existing libredfat..."
fi

# STEP (2): build the binaries
echo -e "${GREEN}$0${OFF}: building the redfat.bin binaries..."
make clean
make redfat.bin
make RedFatPlugin.so
make redfat-rt

rm -rf install
mkdir -p install
mv redfat.bin install
ln -f -s install/redfat.bin
ln -f -s install/redfat.bin redfat

cd install/
ln -f -s ../e9patch-$E9_VERSION/e9patch
ln -f -s ../e9patch-$E9_VERSION/e9tool
ln -f -s ../libredfat-$LIB_VERSION/libredfat.so
ln -f -s ../RedFatPlugin.so
ln -f -s ../redfat-rt

cd ..
ln -f -s install/libredfat.so

echo -e "${GREEN}$0${OFF}: done!"

