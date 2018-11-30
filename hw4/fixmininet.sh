#!/bin/bash

# Run as root, if not already doing so
if [ "`id -u`" -ne 0 ]; then
    sudo $0 $*
    exit $?
fi

# mv /usr/bin/mn /usr/bin/mn.old
# mv /usr/lib/python2.7/dist-packages/mininet-2.2.1-py2.7.egg /usr/lib/python2.7/dist-packages/mininet-2.2.1-py2.7.egg.old
# apt-get install -y mininet
PATCH=/mininet.patch
echo $PATCH
cd /usr/lib/python2.7/dist-packages/mininet/
patch -p1 < $PATCH
