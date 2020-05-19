#!/bin/bash

NAME=${PWD##*/}
rm -f $NAME.tar.gz
COPYFILE_DISABLE=1 tar zcvf $NAME.tar.gz build.sh package.sh test.sh $(ls *.c) $(ls *.h) writeup.md writeup.pdf