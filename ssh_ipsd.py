"""

"""
import re
import os
import time
import subprocess


# Constants taken from configuration file
ATTEMPTS = 3
ATTEMPTS_TIMEOUT = 60
AUTH_LOG_FILE = '/var/log/auth.log'
FIREWALL = 'iptables'
BAN_TIME = 60


def read_config():
	"""
	Reads the running constants from the configuration file.
	"""
	pass

def read_state():
	"""
	Reads the banned addresses from the saved state file
	"""
	pass

def check_regex(line):
	"""
	Checks the line to see if it is a failed login attempt.
	Returns a tuple of 3 elements, 0/1/2 if it was failed or not, 4/6 for the IP version and the address.
	The failed variable becomes 2 if the matched string should be counted 2 times
	"""
	ipv4_re = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	ipv6_re = r"([0-9a-f]*:[0-9a-f:]+)"


	# The 'message repeated 2 times...' expression should be first, otherwise the line will be matched with another expression
	failed_re = (r"(.*message repeated 2 times \[Failed password.* )",
				r"(.*Failed password.* )",
				r"(.*Invalid user.* )",
				r"(.*Did not receive identification.* )",
				r"(.*Received disconnect.*from )",
				)

	accepted_re = r"(.*Accepted password.* )"

	ip_version = 4
	failed = 0
	address = ''

	for variant in failed_re:
		expression = re.compile(variant + ipv4_re)
		if re.match(expression, line) is not None:
			failed = 1
			address = expression.search(line).group(2)

			if variant == r"(.*message repeated 2 times \[Failed password.* )":
				failed = 2
			break

		expression = re.compile(variant + ipv6_re)
		if re.match(expression, line) is not None:
			failed = 1
			ip_version = 6
			address = expression.search(line).group(2)

			if variant == r"(.*message repeated 2 times \[Failed password.* )":
				failed = 2
			break

	# The case in which there was no match for any failure string
	if address == '':
		expression = re.compile(accepted_re + ipv4_re)
		if re.match(expression, line) is not None:
			address = expression.search(line).group(2)

		expression = re.compile(accepted_re + ipv6_re)
		if re.match(expression, line) is not None:
			ip_version = 6
			address = expression.search(line).group(2)

	return (failed, ip_version, address)


def main():
	read_config()
	read_state()


if __name__ == "__main__":
	main()