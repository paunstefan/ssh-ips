import unittest
import ssh_ipsd

class TestRegex(unittest.TestCase):

	def setUp(self):
		pass

	def test_ipv4_1(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Failed password for root from 192.168.93.136 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line),(1, 4, '192.168.93.136'))

	def test_ipv6_1(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Failed password for root from 2001:db8::acab:1 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 6, '2001:db8::acab:1'))


	def test_ipv4_2(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: message repeated 2 times [Failed password for root from 192.168.93.2 port 35343 ssh2]"
		self.assertEqual(ssh_ipsd.check_regex(line), (2, 4, '192.168.93.2'))

	def test_ipv6_2(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: message repeated 2 times [Failed password for root from 2001:db8::acab:2 port 35343 ssh2]"
		self.assertEqual(ssh_ipsd.check_regex(line), (2, 6, '2001:db8::acab:2'))


	def test_ipv4_3(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Invalid user admin from 179.170.183.29"
		self.assertEqual(ssh_ipsd.check_regex(line),(1, 4, '179.170.183.29'))

	def test_ipv6_3(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Invalid user admin from 2a02:2f0c:730c:d800:9d09:dc86:7b88:1f99"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 6, '2a02:2f0c:730c:d800:9d09:dc86:7b88:1f99'))


	def test_ipv4_4(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Did not receive identification string from 222.161.209.43 port 32948"
		self.assertEqual(ssh_ipsd.check_regex(line),(1, 4, '222.161.209.43'))

	def test_ipv6_4(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Did not receive identification string from 2a02:2f0c:730c:d800:9d09:dc86:7b88:1f99 port 32948"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 6, '2a02:2f0c:730c:d800:9d09:dc86:7b88:1f99'))


	def test_ipv4_5(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Received disconnect from 118.123.15.142 port 58149:11:"
		self.assertEqual(ssh_ipsd.check_regex(line),(1, 4, '118.123.15.142'))

	def test_ipv6_5(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Received disconnect from 2001:db8::acab:1 port 58149:11:"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 6, '2001:db8::acab:1'))


	def test_ipv4_special(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Failed password for 10.10.10.2 from 192.168.93.136 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 4, '192.168.93.136'))

	def test_ipv6_special(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Failed password for fe80:acab:2000::0001 from 2001:db8::acab:1 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line), (1, 6, '2001:db8::acab:1'))

	def test_ipv4_succ(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Accepted password for root from 192.168.93.136 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line), (0, 4, '192.168.93.136'))

	def test_ipv6_succ(self):
		line = "Nov 13 16:43:18 ubuntu sshd[213]: Accepted password for root from 192.168.93.136 port 35343 ssh2"
		self.assertEqual(ssh_ipsd.check_regex(line), (0, 4, '192.168.93.136'))

	def test_not_match1(self):
		line = "Nov 17 14:17:01 Skylab-L CRON[9626]: pam_unix(cron:session): session closed for user root"
		self.assertEqual(ssh_ipsd.check_regex(line), (0, 4, ''))

	def test_not_match2(self):
		line = "Nov 16 10:55:26 Skylab-L dbus-daemon[804]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)"
		self.assertEqual(ssh_ipsd.check_regex(line), (0, 4, ''))


if __name__ == '__main__':
	unittest.main()