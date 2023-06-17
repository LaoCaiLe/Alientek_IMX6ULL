#!/bin/bash

if [ -z $1 ]
then
    echo 'Error, target file is not set!'
    exit
fi
if [ $1 == 'clean' ]
then
   echo 'sudo rm -rf /dev/$2'
   sudo rm -rf /dev/$2
   exit
fi
./imxdownload u-boot.bin /dev/$1

