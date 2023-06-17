#!/bin/bash
if [ ! -z $1 ]
then
    make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- distclean
fi
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- mx6ull_14x14_evk_emmc_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -j16

