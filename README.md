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
the **/etc/ssh-ips/config.json** file and edit it to suit your needs. The variables mean 
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

## Software documentation