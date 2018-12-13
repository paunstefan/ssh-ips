import logging
import time

logging.basicConfig(filename="ssh-ips.log", filemode="a", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.DEBUG)


logging.error("Invalid 'trusted_networks' in config.")
time.sleep(1)
logging.info("Banned address 192.168.100.10")
time.sleep(1)
logging.info("Banned address 192.168.100.11")
time.sleep(1)
logging.error("Invalid 'trusted_networks' in config.")
time.sleep(1)
logging.error("Invalid 'trusted_networks' in config.")
time.sleep(1)
logging.info("Banned address 192.168.100.10")
time.sleep(1)
logging.info("Banned address 192.168.100.10")
time.sleep(1)
logging.info("Banned address 192.168.100.100")
time.sleep(1)
logging.info("Banned address 192.168.100.11")
