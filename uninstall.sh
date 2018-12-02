#!/usr/bin/env bash
#
# This script can be used to uninstall SSH-IPS.
#

if ! whoami | grep -q 'root'; then
   echo "You must be root."
   exit 1
fi

systemctl stop ssh-ips
systemctl disable ssh-ips

rm /etc/systemd/system/ssh-ips.service
echo "Removed unit file."
rm -r /usr/local/bin/ssh-ips
echo "Removed executables."
rm -r /etc/ssh-ips
echo "Removed config files."
rm -r /var/lib/ssh-ips
echo "Removed saved state file."
rm /etc/logrotate.d/ssh-ips
echo "Removed logrotate file."
rm /var/log/ssh-ips.log

systemctl daemon-reload
systemctl reset-failed

echo ""