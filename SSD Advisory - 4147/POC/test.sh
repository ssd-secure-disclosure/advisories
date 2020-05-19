#!/bin/bash

SOURCE_HOST=192.168.56.1 # virtualbox host IP
SOURCE_PROJ=cryptodev_race # project being downloaded

echo "Loading cryptodev"
{
	kldload cryptodev && \
	kldload aesni	
} || {
	echo "cryptodev failed to load or already loaded"
}

# Download 
echo "Downloading project"
{
	rm -rf test/ && \
	mkdir test/ && \
	wget http://$SOURCE_HOST:8000/$SOURCE_PROJ.tar.gz -O test/abc.tar.gz --quiet && \
	tar -zxf test/abc.tar.gz -C test/
} || {
	echo "Failed to download latest project"
	exit 1
}

echo "Building project"
{
	cd test/ &&\
	sh build.sh
} || {
	echo "Failed to compile"
	exit 1
}
