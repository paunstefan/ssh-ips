#!/usr/bin/env python3
"""
ssh_ips.py
This file contains the user CLI for SSH-IPS.
"""
import argparse
import sys
import json
from datetime import datetime
import operator


def read_config():
	"""
	Reads the configuration info into the cfg dictionary.
	"""
	#CONFIG_FILE = '/etc/ssh-ips/config.json'
	CONFIG_FILE = 'files/config.json'
	try:
		with open(CONFIG_FILE, "r") as f:
			cfg = json.load(f)
	except ValueError as e:
		print(str(e))
		sys.exit()

	return cfg


def unix_to_human_time(timestamp):
	"""
	Returns a human readable string of the unix timestamp provided.
	"""
	return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def banned_addresses_info(config):
	"""
	Prints information about the banned addresses.
	"""
	state_file = 'extra/state_test.json'		# CHANGE TO FILE FROM CONFIG
	ban_time = 120

	try:
		with open(state_file, "r") as f:
			saved_state = json.load(f)
			# Turns the dictionary into a sorted tuple
			sorted_bans = sorted(saved_state.items(), key=operator.itemgetter(1))
	except ValueError as e:
		print(str(e))
		sys.exit()

	print("Address".ljust(41) + "Banned on (UTC)".ljust(21) + "Banned until (UTC)")

	for ban in sorted_bans:
		print(
			"{}".format(ban[0]).ljust(41) +
			"{}".format(unix_to_human_time(ban[1])).ljust(21) +
			"{}".format(unix_to_human_time(ban[1] + ban_time))
			)


def unban_address(address):
	"""
	Unbans the address received.
	"""
	pass


def show_stats():
	"""
	Shows SSH-IPS statistics.
	"""
	pass


def start():
	"""
	Starts SSH-IPS
	"""
	pass


def stop():
	"""
	Stops SSH-IPS.
	"""
	pass


def restart():
	"""
	Restarts SSH-IPS
	"""
	pass


def main():
	parser = argparse.ArgumentParser(
		description='SSH-IPS client',
		epilog="--config must be used with one of more config variables")
	group = parser.add_mutually_exclusive_group()

	group.add_argument("-c", "--config", action="store_true", help="Change config.")
	group.add_argument("-i", "--info", action="store_true", help="Show banned addresses")
	group.add_argument("-u", "--unban", type=str, help="Unban address")

	parser.add_argument('-t', '--timeout', type=int, help="timeout value")

	arg_number = len(sys.argv)
	if arg_number < 2:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()

	configuration = read_config()
	print(configuration)

	if args.info:
		banned_addresses_info(configuration)

	if args.config:
		if arg_number < 3:
			parser.print_help()
			sys.exit(1)

		if args.timeout:
			pass



if __name__ == "__main__":
	main()
