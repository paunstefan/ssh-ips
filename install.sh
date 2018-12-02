#!/usr/bin/env bash
#
# This script installs SSH-IPS
#

PYTHON_INSTALL=/usr/bin/python3
PROC_MANAGER=systemd

if ! whoami | grep -q 'root'; then
   echo "You must be root to install SSH-IPS."
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
    echo "Example: ln -s [python3 absolute path] /usr/bin/python3"
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

    if [[ ! "PYTHON_INSTALL" = /* ]]; then
        echo "Please use the absolute path."
        echo "You can find it using 'which $PYTHON_INSTALL'"
        exit 1
    fi
fi


function install_systemd {
    # Install the systemd unit file
    cp files/ssh-ips.service /etc/systemd/system
    echo "Installed systemd unit file."

    # Install the executables to their location
    mkdir /usr/local/bin/ssh-ips
    cp ssh_ipsd.py /usr/local/bin/ssh-ips
    cp ssh_ips.py /usr/local/bin/ssh-ips
    echo "Installed executables to /usr/local/bin"

    # Move the default config file
    mkdir /etc/ssh-ips
    cp files/config.json /etc/ssh-ips
    echo "Installed config file to /etc/ssh-ips"

    # Create the saved state file
    mkdir /var/lib/ssh-ips
    touch /var/lib/ssh-ips/saved_state.json
    echo "{}" > /var/lib/ssh-ips/saved_state.json
    echo "Installed saved state file to /var/lib/ssh-ips"

    # Enable logrotate for the SSH-IPS log
    if [ -d "/etc/logrotate.d" ]; then
	    cp files/ssh-ips /etc/logrotate.d
	    chmod 644 /etc/logrotate.d/ssh-ips
	    chown root:root /etc/logrotate.d/ssh-ips
	    echo "Installed logrotate file."
    fi

    echo ""
    echo "SSH-IPS successfully installed!"
    echo ""
    echo "You can now start it using:"
    echo "#systemctl start ssh-ips"
    echo "#systemctl enable ssh-ips"
    echo ""

}

if [ "$PROC_MANAGER" == "systemd" ]; then
	install_systemd
fi