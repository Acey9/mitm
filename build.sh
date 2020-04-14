#!/bin/bash
local_dir=`dirname $0`
cd $local_dir

#git pull

GOPATH=`pwd`:$GOPATH

#echo $GOPATH
mkdir -p build
make
