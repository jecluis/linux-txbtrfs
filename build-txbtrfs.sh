#!/bin/bash

build_dir=/usr/src/builds/btrfs-unstable
src_dir=/usr/src/btrfs-unstable;

ret=0;

cur_dir=`pwd`;
if [ $# -gt 0 ]; then
	if [ $# -ne 2 ]; then
		echo "usage: $0 [<src dir> <build dir>]"
		exit 1;
	fi
	src_dir=$1
	build_dir=$2
	echo "Using $build_dir as build dir. 3 secs to abort."
	sleep 2
fi

cd $src_dir
sudo make O=$build_dir M=fs/btrfs

if [ $? -ne 0 ]; then
    echo "Build finished with errors.";
    ret=1;
fi

cd $cur_dir;

exit $ret;
