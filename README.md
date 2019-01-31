# SSH-IPS

SSH-IPS is an intrusion prevention system that blocks SSH brute force attacks by 
banning the attacking addresses.

## How it works

SSH-IPS monitors the SSH log file (usually /var/log/auth.log) for any changes. 
If there is a change and the new line matches one of the patterns that may mean
someone is attempting to brute-force the machine, it remembers the address of that user.
If there are more than N attempts to login in M minutes it will add an iptables rule
to block that address for a certain amount of time.

It will also notify you if there was a successful login from outside of the networks 
you consider trusted.

## Installation

Requirements:
- Python 3
- iptables
- systemd

To get the source code you can either clone the repository:

````commandline
git clone https://gitlab.com/paunstefan/ssh-ips.git
cd ssh-ips
````

Or download an archive from this page and extract it using you sofware of choice,
after that enter the directory:
````commandline
cd ssh-ips-master
````

Inside you will find the **install.sh** script that will do the installation.

If your Python 3 path is **/usr/bin/python3** you can run the install without any parameters.
Otherwise you must provide the Python 3 path (or manually create a symbolic link
to **/usr/bin/python3**).
````
sudo ./install.sh [python3_path]
````

If there were no errors SSH-IPS will be installed at this point. Before starting check 
the **/etc/ssh-ips/config.json** file and edit it to suit your needs (or see below for CLI instructions). 
The variables mean 
the following:

- _auth_log_file_ 

    The SSH log file. Please modify if needed.
- _attempts_ 

    Number of login attempts before banning the address.
- _attempts_timeout_ 

    Time in seconds before the attempts counter timeouts.
- _saved_state_file_ 

    File where SSH-IPS saves its banned addresses. Do not modify.
- _firewall_ 

    The firewall software that does the banning. Do not modify.
- _ban_time_ 

    Time in seconds the addresses are banned for. Use 0 if you want an infinite ban.
- _send_email_ 

    1 if you want SSH-IPS to send you email notifications, 0 if not. For more info about making
    this feature work see 'Email' in the 'Software documentation' section below.
- _from_email_ 

    Email address from which the emails are send. I recommend making an account especially for this.
- _from_email_password_ 

    Password of the 'from_email' address.
- _to_email_ 

    Email address on which you want to receive the emails.
- _smtp_server_ 

    SMTP server of the 'from_email' address.
- _smtp_port_ 

    SMTP port of the 'from_email' address.
- _trusted_notification_ 

    1 if you want to use the trusted notification function. It will add an entry to the log file
    and send you an email notification (if the send_email variable is on) if there was a successful
    login from other networks than the ones in the following variable.
- _trusted_networks_ 

    A list of your trusted networks. The syntax is: `"trusted_networks": ["192.168.1.0/24",]`

After adding your configuration you can start the program. You can either use the ssh-ips CLI or systemctl:
````
ssh_ips --start
// or
systemctl start ssh-ips
````
To make the software start at boot, enable it with systemctl:
````
systemctl enable ssh-ips
````

Now everything should be up and running.

You can check the log file at _/var/log/ssh-ips.log_.
###CLI
SSH-IPS can be configured and controlled using the ssh_ips CLI interface.

To control or get information from ssh_ipsd.py there are defined the following commands:
- --info / -i

    Shows the banned addresses.
- -stats / -s

    Shows some statistics about SSH-IPS.
- --start / -b

    Starts SSH-IPS.
- --stop / -x
    
    Stops SSH-IPS.
- --restart / -r

    Restarts SSH-IPS.
- --unban [address] / -u [address]

    Unbans the IPv4 or IPv6 address given as parameter.
    
To configure SSH-IPS using the CLI, you must use the --config (-c) parameter together 
with one of the following commands (see above for more explanations):
- --timeout [seconds]

    Changes the attempts_timeout value.
- --log [file]

    Changes the auth_log_file value.
- --attempts [count]

    Changes the attempts value.
- --state [file]

    Changes the saved_state_file value.
- --firewall [name]

    Changes the firewall value.
- --ban_time [seconds]

    Changes the ban_time value.
- --email [0|1]

    Changes the send_email value.
- --from_email [email]

    Changes the from_email value.
- --from_email_pass [pass]

    Changes the from_email_password value.
- --to_email [email]

    Changes the to_email value.
- --smtp_server [server]

    Changes the smtp_server value.
- --smtp_port [port]

    Changes the smtp_port value.
- --trusted [0|1]

    Changes the trusted_notification value.
- --trusted_network_add [network]

    Adds a network to the trusted_networks list.
- --trusted_network_rm [network]

    Removes a network from the trusted_networks list.
    

Example: To to change the ban time to 3600 seconds and add the 10.10.10.0/24 network to the 
trusted list, you can run the following command:
````commandline
ssh_ips -c --ban_time 3600 --trusted_network_add 10.10.10.0/24
````

###Uninstall
If you need to uninstall SSH-IPS you first need to stop the service and disable it in systemd.
````commandline
systemctl stop ssh-ips
systemctl disable ssh-ips
````

Then all you need to do is remove all files related to it:
- The systemctl unit file: _/etc/systemd/system/ssh-ips.service_
- The executables: _/usr/local/bin/ssh-ips_ (directory) and _/usr/local/bin/ssh_ips_
- The config files directory: _/etc/ssh-ips_
- The saved state file: _/var/lib/ssh-ips_
- The logrotate config: _/etc/logrotate.d/ssh-ips_
- The log file: _/var/log/ssh-ips.log_

**Alternative**: You can use the uninstall.sh script provided in the repository.


## Software documentation
### Installed files
SSH-IPS needs the following files to work.
- _/etc/systemd/system/ssh-ips.service_

    The systemd unit file. It describes how systemd should run the SSH-IPS service.
- _/usr/local/bin/ssh-ips/ssh_ipsd.py_

    The main executable.
- _/usr/local/bin/ssh-ips/ssh_ips.py_

    The CLI interface executable. It's hard link can be found at _/usr/local/bin/ssh_ips_
    
- _/etc/ssh-ips/config.json_

    The configuration file. The values from here are read into ssh_ipsd.py at runtime.
- _/var/lib/ssh-ips/saved_state.json_

    The saved state file. Here you can find the currently banned addresses and the timestamp
    they were banned at.
- _/etc/logrotate.d/ssh-ips_

    The logrotate config. Logrotate is a Linux utility that archives and eventually deletes
    old logs from the system.

###Email
SSH-IPS can send you an email if the send_email and trusted_notification configurations are 
both turned on. In this case, the email will be sent if there was a successful login 
from an untrusted network.

The email configuration is not the simplest and I will explain it here how to make it work 
for Gmail (it should be easier for a personal email server). I recommend creating a special
address just for SSH-IPS, as the password is stored in plain text.

First thing after you created the Gmail address is to go to https://www.google.com/settings/security/lesssecureapps
and enable access for less secure apps. 

After that, go to the configuration file (/etc/ssh-ips/config.json) and change the following values:

- "send_email": 1

- "from_email": "[your_new_address]"

- "from_email_password": "[your_new_password]"

- "to_email": "[address_to_receive_emails]"

- "smtp_server": "smtp.gmail.com" _(specific for Gmail)_

- "smtp_port": 587 _(specific for Gmail)_

If you use a personal email server, use your own smtp_server address and smtp_port.

