#!/usr/bin/env python3
"""
ssh_ips.py
This file contains the user CLI for SSH-IPS.
"""
import argparse
import sys
import os.path
import json
from datetime import datetime
import operator
import subprocess
import ipaddress
import time


def read_config():
	"""
	Reads the configuration info into the cfg dictionary.
	"""
	CONFIG_FILE = '/etc/ssh-ips/config.json'
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
	state_file = config['saved_state_file']
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


def unban_address(address, cfg):
	"""
	Unbans the address received.
	Executes the iptables command, decrements the saved state entry by the ban time and restarts ssh_ipsd.
	"""
	with open(cfg["saved_state_file"], "r") as f:
		banned_addresses = json.load(f)

	firewall = cfg['firewall']

	# If the ban is infinite, ssh_ipsd never removes addresses from the saved state file
	# so I need to remove them here.
	infinite_ban = False
	if cfg['ban_time'] == 0:
		infinite_ban = True

	unban_all = False

	if address == 'all':
		unban_all = True
		for addr in banned_addresses:
			banned_addresses[addr] -= cfg['ban_time']
			if firewall == 'iptables':
				if ':' in addr:
					subprocess.run(['ip6tables', '-D', 'INPUT', '-s', addr, '-j', 'DROP'])
				else:
					subprocess.run(['iptables', '-D', 'INPUT', '-s', addr, '-j', 'DROP'])

			if infinite_ban:
				banned_addresses.pop(addr)

		print("All addresses unbanned successfully!")

	if not unban_all:
		if address not in banned_addresses:
			print("Error: address is not banned")
			sys.exit(1)
		banned_addresses[address] -= cfg['ban_time']
		if firewall == 'iptables':
			if ':' in address:
				subprocess.run(['ip6tables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])
			else:
				subprocess.run(['iptables', '-D', 'INPUT', '-s', address, '-j', 'DROP'])

		if infinite_ban:
			banned_addresses.pop(address)
		print("Address {} unbanned!".format(address))

	with open(cfg["saved_state_file"], "w") as f:
		json.dump(banned_addresses, f)

	restart()




def show_stats(cfg):
	"""
	Shows SSH-IPS statistics.
	"""
	log_file = "/var/log/ssh-ips.log"

	try:
		with open(log_file, "r") as f:
			logs = f.read().splitlines()
	except Exception as e:
		print(str(e))
		sys.exit()

	beginning_time = logs[0].split(',')[0]
	beginning_date = beginning_time.split()[0]
	beginning_time = time.mktime(time.strptime(beginning_time, '%Y-%m-%d %H:%M:%S'))
	# Time difference in hours since the first entry in the log file
	time_diff = ((time.time() - beginning_time) / 60) / 60

	ban_count = 0
	banned_addresses = dict()

	for line in logs:
		if line.split()[3] == "Banned":
			ban_count += 1

			banned_addresses.setdefault(line.split()[5], 0)
			banned_addresses[line.split()[5]] += 1

	sorted_bans = sorted(banned_addresses.items(), key=operator.itemgetter(1))
	sorted_bans.reverse()

	print("Total bans since {}: {}".format(beginning_date, ban_count))
	print("Bans per hour: {}".format(ban_count/time_diff))
	print("Most banned address: {} - {} bans".format(sorted_bans[0][0], sorted_bans[0][1]))


def start():
	"""
	Starts SSH-IPS
	"""
	subprocess.run(['/bin/systemctl', 'start', 'ssh-ips'])


def stop():
	"""
	Stops SSH-IPS.
	"""
	try:
		subprocess.run(['/bin/systemctl', 'stop', 'ssh-ips'])
	except FileNotFoundError:
		print("You have not started ssh-ips.")



def restart():
	"""
	Restarts SSH-IPS
	"""
	try:
		subprocess.run(['/bin/systemctl', 'restart', 'ssh-ips'])
	except FileNotFoundError:
		print("You have not started ssh-ips.")


def update_config(cfg):
	"""
	Updates SSH-IPS config and restarts the daemon.
	"""
	CONFIG_FILE = '/etc/ssh-ips/config.json'
	try:
		with open(CONFIG_FILE, "w") as f:
			json.dump(cfg, f, indent=2)
	except ValueError as e:
		print(str(e))
		sys.exit()

	restart()

def main():
	parser = argparse.ArgumentParser(
		description='SSH-IPS client',
		epilog="--config must be used with one of more config variables")
	group = parser.add_mutually_exclusive_group()

	# Command line arguments
	group.add_argument("-c", "--config", action="store_true", help="Change config.")
	group.add_argument("-i", "--info", action="store_true", help="Show banned addresses")
	group.add_argument("-u", "--unban", type=str, help="Unban address")
	group.add_argument("-b", "--start", action="store_true", help="Start SSH-IPS")
	group.add_argument("-x", "--stop", action="store_true", help="Stop SSH-IPS")
	group.add_argument("-r", "--restart", action="store_true", help="Restart SSH-IPS")
	group.add_argument("-s", "--stats", action="store_true", help="Stop SSH-IPS")

	parser.add_argument('--timeout', type=int, help="timeout value")
	parser.add_argument('--log', type=str, help="auth log file")
	parser.add_argument('--attempts', type=int, help="attempts count")
	parser.add_argument('--state', type=str, help="save state file")
	parser.add_argument('--firewall', type=str, help="firewall")
	parser.add_argument('--ban_time', type=int, help="ban time")
	parser.add_argument('--email', type=int, help="send email (1 or 0)")
	parser.add_argument('--from_email', type=str, help="source email address")
	parser.add_argument('--from_email_pass', type=str, help="source email address password")
	parser.add_argument('--to_email', type=str, help="destination email address")
	parser.add_argument('--smtp_server', type=str, help="smtp server")
	parser.add_argument('--smtp_port', type=int, help="smtp server port")
	parser.add_argument('--trusted', type=int, help="trusted notification (1 or 0)")
	parser.add_argument('--trusted_network_add', type=str, help="add trusted network")
	parser.add_argument('--trusted_network_rm', type=str, help="remove trusted network")


	arg_number = len(sys.argv)
	if arg_number < 2:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()

	configuration = read_config()

	if args.info:
		if arg_number != 2:
			parser.print_help()
			sys.exit(1)
		banned_addresses_info(configuration)

	if args.stats:
		if arg_number != 2:
			parser.print_help()
			sys.exit(1)
		show_stats(configuration)

	if args.unban is not None:
		if arg_number != 3:
			parser.print_help()
			sys.exit(1)
		unban_address(args.unban, configuration)

	if args.start:
		start()

	if args.stop:
		stop()

	if args.restart:
		restart()

	# Here start the configuration changes
	if args.config:
		if arg_number < 3:
			parser.print_help()
			sys.exit(1)

		if args.timeout is not None:
			if args.timeout <= 0:
				print("Error: timeout must be > 0")
				sys.exit(1)
			configuration["attempts_timeout"] = args.timeout

		if args.log is not None:
			if not os.path.isfile(args.log):
				print("Error: log file does not exist")
				sys.exit(1)
			configuration["auth_log_file"] = args.log

		if args.attempts is not None:
			if args.attempts < 1:
				print("Error: attempts counter must be > 0")
				sys.exit(1)
			configuration["attempts"] = args.attempts

		if args.state is not None:
			if not os.path.isfile(args.state):
				print("Error: state file does not exist")
				sys.exit(1)
			configuration["saved_state_file"] = args.state

		if args.firewall is not None:
			if args.firewall != 'iptables':
				print("Error: firewall not supported")
				sys.exit(1)
			configuration["firewall"] = args.firewall

		if args.ban_time is not None:
			if args.ban_time < 0:
				print("Error: ban time must be >=0")
				sys.exit(1)
			configuration["ban_time"] = args.ban_time

		if args.email is not None:
			if args.email not in [0, 1]:
				print("Error: email must be 0 or 1")
				sys.exit(1)
			configuration["send_email"] = args.email

		if args.from_email is not None:
			configuration["from_email"] = args.from_email

		if args.from_email_pass is not None:
			configuration["from_email_pass"] = args.from_email_pass

		if args.to_email is not None:
			configuration["to_email"] = args.to_email

		if args.smtp_server is not None:
			configuration["smtp_server"] = args.smtp_server

		if args.smtp_port is not None:
			if args.smtp_port < 1:
				print("Error: smtp_server_port not valid")
				sys.exit(1)
			configuration["smtp_port"] = args.smtp_port

		if args.trusted is not None:
			if args.trusted not in [0, 1]:
				print("Error: trusted must be 0 or 1")
				sys.exit(1)
			configuration["trusted_notification"] = args.trusted

		if args.trusted_network_add is not None:
			if args.trusted_network_add in configuration["trusted_networks"]:
				print("Error: trusted address already exists")
				sys.exit(1)
			try:
				ipaddress.ip_network(args.trusted_network_add)
				configuration["trusted_networks"].append(args.trusted_network_add)
			except ValueError:
				print("Error: trusted_network not valid")
				sys.exit(1)

		if args.trusted_network_rm is not None:
			configuration["trusted_networks"].remove(args.trusted_network_rm)

		update_config(configuration)


if __name__ == "__main__":
	main()
