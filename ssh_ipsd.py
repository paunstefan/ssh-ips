"""

"""
import re
import os
import time
import subprocess
import ipaddress
import json

import logging

logging.basicConfig(level=logging.DEBUG)		# Comment when not needed

# Constants taken from configuration file
ATTEMPTS = 3
ATTEMPTS_TIMEOUT = 60
AUTH_LOG_FILE = '/var/log/auth.log'
SAVED_STATE_FILE = 'saved_state.json'
BANNED_ADDRESSES = dict()
LOG_FILE = ''
FIREWALL = 'iptables'
BAN_TIME = 60
SEND_EMAIL = False
EMAIL_ADDRESS = ''
TRUSTED_NETWORKS = ''


def read_config():
	"""
	Reads the running constants from the configuration file.
	"""
	pass


def read_state():
	"""
	Reads the banned addresses from the saved state file
	"""
	# global keyword so I can reassign the global variable inside the function
	global BANNED_ADDRESSES
	with open(SAVED_STATE_FILE, "r") as f:
		BANNED_ADDRESSES = json.load(f)


def log_action():
	"""
	Writes entries to the SSH-IPS log file.
	"""
	pass


def save_file_operation(action, address):
	"""
	Writes or deletes addresses from the saved state file.
	The action parameter can be 0 if the action is 'delete' and 1 if the action is 'write'.
	"""
	if action == 0:
		BANNED_ADDRESSES.pop(address)
		with open(SAVED_STATE_FILE, "w") as f:
			json.dump(BANNED_ADDRESSES, f)

	elif action == 1:
		BANNED_ADDRESSES[address] = time.time()
		logging.debug(BANNED_ADDRESSES)
		with open(SAVED_STATE_FILE, "w") as f:
			json.dump(BANNED_ADDRESSES, f)


def check_regex(line):
	"""
	Checks the line to see if it is a failed login attempt.
	Returns a tuple of 3 elements, 0/1/2 if it was failed or not, 4/6 for the IP version and the address.
	The failed variable becomes 2 if the matched string should be counted 2 times.
	Example: (1, 4, "192.168.1.1") means that it was a failed attempt from the IPv4 address "192.168.1.1".
	"""
	ipv4_re = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	ipv6_re = r"([0-9a-f]*:[0-9a-f:]+)"

	# The 'message repeated 2 times...' expression should be first, otherwise the line will be matched with another expression
	failed_re = (r"(.*message repeated 2 times.*Failed password.* )",
				r"(.*Failed password.* )",
				r"(.*Invalid user.* )",
				r"(.*Did not receive identification.* )",
				r"(.*Received disconnect.*from )",
				)

	accepted_re = r"(.*Accepted password.* )"

	ip_version = 4
	failed = 0
	address = ''

	# I'm sure this can be done more efficient
	for variant in failed_re:
		expression = re.compile(variant + ipv4_re)
		if re.match(expression, line) is not None:
			failed = 1
			address = expression.search(line).group(2)

			if variant == r"(.*message repeated 2 times.*Failed password.* )":
				logging.debug("REACHED THIS")										# DELETE THIS
				failed = 2
			break

		expression = re.compile(variant + ipv6_re)
		if re.match(expression, line) is not None:
			failed = 1
			ip_version = 6
			address = expression.search(line).group(2)

			if variant == r"(.*message repeated 2 times.*Failed password.* )":
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


def handle_login(attempt, temp_addresses):
	"""
	Handles the result of the check_regex() function.
	It modifies the temporary_addresses dictionary and can invoke the block_address() or untrusted_notification() functions.
	attempt is the tuple returned by check_regex(); example: (1, 4, "10.10.2.1")
	temp_addresses is a dictionary that stores addresses until they timeout or they are blocked
		structure: {address: [nr_attempts, timestamp],}
	"""
	if attempt[0] == 0 and TRUSTED_NETWORKS != '':
		untrusted_notification(attempt[2])

	elif attempt[0] > 0:
		# I first check if the addresses timed out, if yes, I delete them
		timeout = list()
		for addr in temp_addresses.keys():
			if time.time() - temp_addresses[addr][1] >= ATTEMPTS_TIMEOUT:
				timeout.append(addr)										# I add the address to the timeout list
		for addr in timeout:
			temp_addresses.pop(addr)										# Addresses in the list are deleted from the dict

		# Then I try to add the address to the dict, if it already exists, I just increment the counter
		temp_addresses.setdefault(attempt[2], [0, time.time()])
		temp_addresses[attempt[2]][0] += attempt[0]
		if temp_addresses[attempt[2]][0] >= ATTEMPTS:
			temp_addresses.pop(attempt[2])
			block_address(attempt)


def block_address(address):
	"""
	Handles the blocking of the address by executing the firewall command needed.
	"""
	if address[1] == 4:
		if FIREWALL == "iptables":
			# insert rule here
			logging.debug("Banned address {}".format(address[2]))
			pass
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	elif address[1] == 6:
		if FIREWALL == "iptables":
			# insert rule here
			pass
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	save_file_operation(1, address[2])

def unban_address(address):
	"""
	Handles the unblocking of the addresses.
	"""
	version = 4
	if ":" in address:
		version = 6

	if version == 4:
		if FIREWALL == "iptables":
			logging.debug("UnBanned address {}".format(address))
			pass
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	elif version == 6:
		if FIREWALL == "iptables":
			# insert rule here
			pass
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	save_file_operation(0, address)


def untrusted_notification(address):
	"""
	It sends a notification to the user if there was a successful login from an untrusted network.
	"""
	trusted = 0
	for network in TRUSTED_NETWORKS:

		# The ipaddress module can easily check if an address is part of a network.
		if ipaddress.ip_address(address) in ipaddress.ip_network(network):
			trusted = 1
			break

	if trusted == 0:
		# SEND NOTIFICATION
		pass


def check_bans():
	"""
	Checks if any bans have expired to delete them. 
	"""
	# I add to the list the unbannable addresses because I can't modify the dict during iteration
	unbannable = list()
	for address in BANNED_ADDRESSES.keys():
		if time.time() - BANNED_ADDRESSES[address] >= BAN_TIME:
			unbannable.append(address)

	for address in unbannable:
		unban_address(address)


def main():
	LOOP_SLEEP_TIME = 0.1
	read_config()
	read_state()
	logging.debug(BANNED_ADDRESSES)

	temporary_addresses = dict()		# This stores the addresses until the timeout expires

	logging.debug("SSH-IPS STARTED")

	# Counts the lines so I can check them all if added in one write (or between my reads)
	line_count_initial = int(subprocess.check_output(['wc', '-l', AUTH_LOG_FILE]).split()[0])

	# The main loop
	while True:
		time.sleep(LOOP_SLEEP_TIME)											# Stops the CPU from maxing out
		check_bans()
		try:
			line_count_current = int(subprocess.check_output(['wc', '-l', AUTH_LOG_FILE]).split()[0])

			if line_count_initial < line_count_current:
				# I want to get the negative value so I can directly use it as argument for tail
				difference = str(line_count_initial - line_count_current)

				# Gets all the new lines added to the file
				lines = subprocess.check_output(['tail', difference, AUTH_LOG_FILE]).decode("utf-8").split('\n')

				for line in lines:
					result = check_regex(line)
					if result[2] != '':
						logging.debug(line)
						logging.debug(result)
						handle_login(result, temporary_addresses)
						logging.debug(temporary_addresses)


			line_count_initial = line_count_current
		except Exception as e:
			logging.debug(str(e))


if __name__ == "__main__":
	main()