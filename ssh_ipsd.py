"""

"""
import re
import sys
import time
import subprocess
import ipaddress
import json
import logging

logging.basicConfig(filename="ssh-ips.log", filemode="a", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.DEBUG)

# Constants taken from configuration file
ATTEMPTS = 3
ATTEMPTS_TIMEOUT = 60
AUTH_LOG_FILE = '/var/log/auth.log'
CONFIG_FILE = 'files/config.json'
SAVED_STATE_FILE = 'files/saved_state.json'
BANNED_ADDRESSES = dict()
FIREWALL = 'iptables'
BAN_TIME = 60
SEND_EMAIL = False
FROM_EMAIL = ''
FROM_EMAIL_PASSWORD = ''
SMTP_SERVER = ''
SMTP_PORT = 0
TO_EMAIL = ''
TRUSTED_NOTIFICATION = 0
TRUSTED_NETWORKS = list()


def read_config():
	"""
	Reads the running constants from the configuration file.
	"""
	global ATTEMPTS
	global ATTEMPTS_TIMEOUT
	global AUTH_LOG_FILE
	global SAVED_STATE_FILE
	global FIREWALL
	global BAN_TIME
	global SEND_EMAIL
	global FROM_EMAIL
	global FROM_EMAIL_PASSWORD
	global TO_EMAIL
	global SMTP_SERVER
	global SMTP_PORT
	global TRUSTED_NOTIFICATION
	global TRUSTED_NETWORKS

	try:
		with open(CONFIG_FILE, "r") as f:
			data = json.load(f)
	except ValueError:
		logging.ERROR("Could not parse config.json")
		sys.exit()

	try:
		if data['attempts'] > 0 and isinstance(data['attempts'], int):
			ATTEMPTS = data['attempts']
		else:
			logging.error("Invalid 'attempts' in config.")
			sys.exit()

		if data['attempts_timeout'] > 0 and isinstance(data['attempts_timeout'], int):
			ATTEMPTS_TIMEOUT = data['attempts_timeout']
		else:
			logging.error("Invalid 'attempts_timeout' in config.")
			sys.exit()

		if data['auth_log_file'] != "" and isinstance(data['auth_log_file'], str):
			AUTH_LOG_FILE = data['auth_log_file']
		else:
			logging.error("Invalid 'auth_log_file' in config.")
			sys.exit()

		if data['saved_state_file'] != "" and isinstance(data['saved_state_file'], str):
			SAVED_STATE_FILE = data['saved_state_file']
		else:
			logging.error("Invalid 'saved_state_file' in config.")
			sys.exit()

		if data['firewall'] in ['iptables', 'nftables'] and isinstance(data['firewall'], str):
			FIREWALL = data['firewall']
		else:
			logging.error("Invalid 'firewall' in config.")
			sys.exit()

		if data['ban_time'] > -1 and isinstance(data['ban_time'], int):
			BAN_TIME = data['ban_time']
		else:
			logging.error("Invalid 'ban_time' in config.")
			sys.exit()

		if data['send_email'] == 1:
			if data['from_email'] != "" and isinstance(data['from_email'], str):
				FROM_EMAIL = data['from_email']
			else:
				logging.error("Invalid 'from_email' in config.")
				sys.exit()

			if data['from_email_password'] != "" and isinstance(data['from_email_password'], str):
				FROM_EMAIL_PASSWORD = data['from_email_password']
			else:
				logging.error("Invalid 'from_email_password' in config.")
				sys.exit()

			if data['to_email'] != "" and isinstance(data['to_email'], str):
				TO_EMAIL = data['to_email']
			else:
				logging.error("Invalid 'to_email' in config.")
				sys.exit()

			if data['smtp_server'] != "" and isinstance(data['smtp_server'], str):
				SMTP_SERVER = data['smtp_server']
			else:
				logging.error("Invalid 'smtp_server' in config.")
				sys.exit()

			if data['smtp_port'] > 0 and isinstance(data['smtp_port'], int):
				SMTP_PORT = data['smtp_port']
			else:
				logging.error("Invalid 'smtp_port' in config.")
				sys.exit()

			if data['trusted_notification'] == 1 and isinstance(data['trusted_notification'], int):
				if len(data['trusted_networks']) == 0 and isinstance(data['trusted_networks'], list):
					TRUSTED_NETWORKS = data['trusted_networks']
				else:
					logging.error("Invalid 'trusted_networks' in config.")
					sys.exit()

	except Exception as e:
		logging.error(str(e))
		sys.exit()


def read_state():
	"""
	Reads the banned addresses from the saved state file
	"""
	# global keyword so I can reassign the global variable inside the function
	global BANNED_ADDRESSES
	try:
		with open(SAVED_STATE_FILE, "r") as f:
			BANNED_ADDRESSES = json.load(f)
	except Exception as e:
		logging.error(str(e))
		sys.exit()


def send_email(message):
	"""
	Sends notification emails to alert the user.
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
	if attempt[0] == 0 and TRUSTED_NOTIFICATION == 1:
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
	It receives the address 3 element tuple.
	"""
	if address[1] == 4:
		if FIREWALL == "iptables":
			subprocess.run(['iptables', '-I', 'INPUT', '-s', address[2], '-j', 'DROP'])
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	elif address[1] == 6:
		if FIREWALL == "iptables":
			subprocess.run(['ip6tables', '-I', 'INPUT', '-s', address[2], '-j', 'DROP'])
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	logging.info("Banned address {}".format(address[2]))

	save_file_operation(1, address[2])

def unban_address(address):
	"""
	Handles the unblocking of the addresses.
	It receives the address string.
	"""
	version = 4
	if ":" in address:
		version = 6

	if version == 4:
		if FIREWALL == "iptables":
			subprocess.run(['iptables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	elif version == 6:
		if FIREWALL == "iptables":
			subprocess.run(['ip6tables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])
		elif FIREWALL == "nftables":
			#insert rule here
			pass

	logging.info("Unbanned address {}".format(address))

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
	logging.info("SSH-IPS STARTED")
	LOOP_SLEEP_TIME = 0.1
	read_config()
	read_state()

	temporary_addresses = dict()		# This stores the addresses until the timeout expires

	logging.info("Initialization finished.")

	# Counts the lines so I can check them all if added in one write (or between my reads)
	line_count_initial = int(subprocess.check_output(['wc', '-l', AUTH_LOG_FILE]).split()[0])

	# The main loop
	while True:
		time.sleep(LOOP_SLEEP_TIME)											# Stops the CPU from maxing out

		# If BAN_TIME is <= 0 it is an infinite ban
		if BAN_TIME > 0:
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
			logging.error(str(e))


if __name__ == "__main__":
	main()
