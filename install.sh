#!/usr/bin/env bash
#
# This script installs SSH-IPS
#

PYTHON_INSTALL=/usr/bin/python3
PROC_MANAGER=systemd

if ! whoami | grep -q 'root'; then
   echo "You must be root to install SSH-IPS"
   exit 1
fi

if ! stat /proc/1/exe | head -1 | grep -q 'systemd'; then
	echo "Process manager not supported."
	echo "SSH-IPS works only with systemd."
	echo "You may be able to install it manually (check README)."
	exit 1
fi

if [ ! -f $PYTHON_INSTALL ]; then
    echo "Default Python 3 install not found."
    echo "Please manually enter the Python 3 interpreter or create a link to /usr/bin/python3 (recommended)."
    echo "Example: ln -s [python3 full path] /usr/bin/python3"
    echo "Example: ./install.sh [python3 full path]"
    exit 1
fi

if [ $# -gt 1 ]; then
    echo "Too many parameters"
    echo "Usage: ./install.sh [python3 full path]"
    exit 1
fi


function change_python {
    sed -i "s|/usr/bin/python3|$PYTHON_INSTALL|g" shtest        # REPLACE THIS FILE HERE
}


if [ $# -eq 1 ]; then
    PYTHON_INSTALL=$1
    change_python
    if [ ! -f $PYTHON_INSTALL ]; then
        echo "Interpreter not found"
        exit 1
    fi
fi


function install_systemd {
	echo "Installing using systemd"

}

if [ "$PROC_MANAGER" == "systemd" ]; then
	install_systemd
fi