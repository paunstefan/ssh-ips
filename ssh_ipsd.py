#!/usr/bin/env python3
"""
ssh_ipsd.py
This file contains the main SSH-IPS daemon.
"""
import re
import sys
import time
import subprocess
import ipaddress
import json
import logging

logging.basicConfig(filename="/var/log/ssh-ips.log", filemode="a", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.INFO)

# Constants taken from configuration file
ATTEMPTS = 3
ATTEMPTS_TIMEOUT = 60
AUTH_LOG_FILE = '/var/log/auth.log'
CONFIG_FILE = '/etc/ssh-ips/config.json'
SAVED_STATE_FILE = '/var/lib/ssh-ips/saved_state.json'
BANNED_ADDRESSES = dict()
FIREWALL = 'iptables'
BAN_TIME = 60
SEND_EMAIL = 0
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
		sys.exit(1)

	try:
		if data['attempts'] > 0 and isinstance(data['attempts'], int):
			ATTEMPTS = data['attempts']
		else:
			logging.error("Invalid 'attempts' in config.")
			sys.exit(1)

		if data['attempts_timeout'] > 0 and isinstance(data['attempts_timeout'], int):
			ATTEMPTS_TIMEOUT = data['attempts_timeout']
		else:
			logging.error("Invalid 'attempts_timeout' in config.")
			sys.exit(1)

		if data['auth_log_file'] != "" and isinstance(data['auth_log_file'], str):
			AUTH_LOG_FILE = data['auth_log_file']
		else:
			logging.error("Invalid 'auth_log_file' in config.")
			sys.exit(1)

		if data['saved_state_file'] != "" and isinstance(data['saved_state_file'], str):
			SAVED_STATE_FILE = data['saved_state_file']
		else:
			logging.error("Invalid 'saved_state_file' in config.")
			sys.exit(1)

		if data['firewall'] in ['iptables', ] and isinstance(data['firewall'], str):
			FIREWALL = data['firewall']
		else:
			logging.error("Invalid 'firewall' in config.")
			sys.exit(1)

		if data['ban_time'] > -1 and isinstance(data['ban_time'], int):
			BAN_TIME = data['ban_time']
		else:
			logging.error("Invalid 'ban_time' in config.")
			sys.exit(1)

		if data['send_email'] in [0, 1]:
			SEND_EMAIL = data['send_email']
		else:
			logging.error("Invalid 'send_email' in config.")
			sys.exit(1)


		if SEND_EMAIL == 1:
			if data['from_email'] != "" and isinstance(data['from_email'], str):
				FROM_EMAIL = data['from_email']
			else:
				logging.error("Invalid 'from_email' in config.")
				sys.exit(1)

			if data['from_email_password'] != "" and isinstance(data['from_email_password'], str):
				FROM_EMAIL_PASSWORD = data['from_email_password']
			else:
				logging.error("Invalid 'from_email_password' in config.")
				sys.exit(1)

			if data['to_email'] != "" and isinstance(data['to_email'], str):
				TO_EMAIL = data['to_email']
			else:
				logging.error("Invalid 'to_email' in config.")
				sys.exit(1)

			if data['smtp_server'] != "" and isinstance(data['smtp_server'], str):
				SMTP_SERVER = data['smtp_server']
			else:
				logging.error("Invalid 'smtp_server' in config.")
				sys.exit(1)

			if data['smtp_port'] > 0 and isinstance(data['smtp_port'], int):
				SMTP_PORT = data['smtp_port']
			else:
				logging.error("Invalid 'smtp_port' in config.")
				sys.exit(1)

		if data['trusted_notification'] in [0, 1]:
			TRUSTED_NOTIFICATION = data['trusted_notification']
		else:
			logging.error("Invalid 'trusted_notification' in config.")
			sys.exit(1)

		if isinstance(data['trusted_networks'], list):
			try:
				for addr in data['trusted_networks']:
					ipaddress.ip_network(addr)
				TRUSTED_NETWORKS = data['trusted_networks']
			except ValueError:
				logging.error("Invalid 'trusted_networks' in config.")
				sys.exit(1)
		else:
			logging.error("Invalid 'trusted_networks' in config.")
			sys.exit(1)

	except Exception as e:
		logging.error(str(e))
		sys.exit(1)


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
		sys.exit(1)


def send_email(message):
	"""
	Sends notification emails to alert the user.
	:param message: The string you want to send.
	"""
	import smtplib
	try:
		server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

		server.ehlo()
		server.starttls()
		server.ehlo()

		server.login(FROM_EMAIL, FROM_EMAIL_PASSWORD)

		msg = "\r\n".join([
			"From: {}".format(FROM_EMAIL),
			"To: {}".format(TO_EMAIL),
			"Subject: SSH-IPS",
			"",
			message
		])

		server.sendmail(FROM_EMAIL, TO_EMAIL, msg)
		server.quit()
	except smtplib.SMTPAuthenticationError:
		logging.error("SMTP Authentication error.")
	except:
		logging.error("Error sending email.")


def send_email_process(message):
	"""
	Creates a new process that will send the email.
	:param message: The string you want to send.
	"""
	from multiprocessing import Process

	# It doesn't work using threading so I am using Process
	p = Process(target=send_email, args=(message,))
	p.daemon = True
	p.start()


def save_file_operation(action, address):
	"""
	Writes or deletes addresses from the saved state file.
	Save format: {'address':timestamp}
	:param action: 0 if the action is 'delete', 1 if the action is 'write'.
	:param address: The address you want to add or remove.
	"""
	if action == 0:
		BANNED_ADDRESSES.pop(address)
		with open(SAVED_STATE_FILE, "w") as f:
			json.dump(BANNED_ADDRESSES, f)

	elif action == 1:
		BANNED_ADDRESSES[address] = time.time()
		with open(SAVED_STATE_FILE, "w") as f:
			json.dump(BANNED_ADDRESSES, f)


def check_regex(line):
	"""
	Checks the line to see if it is a failed login attempt.
	The failed variable becomes 2 if the matched string should be counted 2 times.
	Example: (1, 4, "192.168.1.1") means that it was a failed attempt from the IPv4 address "192.168.1.1".
	:param line: The line read from the auth log.
	:return: A tuple of 3 elements, 0/1/n if it was failed or not, 4/6 for the IP version and the address.
	"""
	ipv4_re = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	ipv6_re = r"([0-9a-f]*:[0-9a-f:]+)"

	# The 'message repeated N times...' expression should be first, otherwise the line will be matched with another expression
	failed_re = (
				r"(.*message repeated (\d*) times.*Failed password.* )",
				r"(.*Failed password.* )",
				r"(.*Invalid user.* )",
				r"(.*Did not receive identification.* )",
				r"(.*Unable to negotiate with.* )",
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

			if variant == r"(.*message repeated (\d*) times.*Failed password.* )":
				address = expression.search(line).group(3)
				failed = int(expression.search(line).group(2))
			break

		expression = re.compile(variant + ipv6_re)
		if re.match(expression, line) is not None:
			failed = 1
			ip_version = 6
			address = expression.search(line).group(2)

			if variant == r"(.*message repeated (\d*) times.*Failed password.* )":
				address = expression.search(line).group(3)
				failed = int(expression.search(line).group(2))
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
	:param attempt: The tuple returned by check_regex(); example: (1, 4, "10.10.2.1")
	:param temp_addresses: A dictionary that stores addresses until they timeout or they are blocked
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
	:param address: 3 element tuple from the check_regex() function.
	"""
	if address[1] == 4:
		if FIREWALL == "iptables":
			subprocess.run(['iptables', '-I', 'INPUT', '-s', address[2], '-j', 'DROP'])

	elif address[1] == 6:
		if FIREWALL == "iptables":
			subprocess.run(['ip6tables', '-I', 'INPUT', '-s', address[2], '-j', 'DROP'])

	logging.info("Banned address {}".format(address[2]))
	save_file_operation(1, address[2])


def unban_address(address):
	"""
	Handles the unblocking of the addresses.
	:param address: A string with the address.
	"""
	version = 4
	if ":" in address:
		version = 6

	if version == 4:
		if FIREWALL == "iptables":
			subprocess.run(['iptables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])

	elif version == 6:
		if FIREWALL == "iptables":
			subprocess.run(['ip6tables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])

	logging.info("Unbanned address {}".format(address))
	save_file_operation(0, address)


def untrusted_notification(address):
	"""
	It sends a notification to the user if there was a successful login from an untrusted network.
	:param address: String with the address.
	"""
	trusted = 0
	for network in TRUSTED_NETWORKS:

		# The ipaddress module can easily check if an address is part of a network.
		if ipaddress.ip_address(address) in ipaddress.ip_network(network):
			trusted = 1
			break

	if trusted == 0:
		logging.info("Untrusted login from address: {}".format(address))
		if SEND_EMAIL == 1:
			send_email_process("Untrusted login from address: {}".format(address))


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

			line_count_initial = line_count_current
		except Exception as e:
			logging.error(str(e))


if __name__ == "__main__":
	main()
