#!/bin/bash

echo "Cleaning up old objects"

{
	rm -f *.o hack
	echo "Cleanup complete"
} || {
	echo "Failed to cleanup"
	exit 1
}

CC=gcc
CLFAGS="-std=c11"

if [ "$(which freebsd-version)" != '' ]; then
	CFLAGS="$CLFAGS -DREAL_BUILD=1"
	echo "Found other compiler";
fi

{
	echo "Building..."
	$CC -g -c $CFLAGS hack.c -o hack.o && \
	$CC -g -c $CFLAGS spray.c -o spray.o  && \
	$CC hack.o spray.o -o hack -g -lpthread
	echo "Done."
} || {
	echo "Failed to build."
	exit 1
}
