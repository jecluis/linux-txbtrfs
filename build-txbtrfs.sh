#!/bin/bash

build_dir=/usr/src/builds/btrfs-unstable
cur_dir=`pwd`;

ret=0;

cd /usr/src/btrfs-unstable;
sudo make O=$build_dir M=fs/btrfs

if [ $? -ne 0 ]; then
    echo "Build finished with errors.";
    ret=1;
fi

cd $cur_dir;

exit $ret;
