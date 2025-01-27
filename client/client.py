import sys
import json
import argparse
import socket
import re
from config import SERVER_PORT, LOOPBACK_ADDRESS

import logging
from traffic_logger import logger_setup

logger_setup()
logger = logging.getLogger(__name__)


class CommandSender:
    """A class to send commands to a server using UDP."""
    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))

    @staticmethod
    def send_message_to_server(message: str) -> None:
        """Send a message to the server using UDP."""
        try:
            logger.info(f"Sending message to Server {LOOPBACK_ADDRESS}:{SERVER_PORT}")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            client_socket.sendto(message.encode(), (LOOPBACK_ADDRESS, SERVER_PORT))

            response, _ = client_socket.recvfrom(1024)
            decoded_response = response.decode()
            logger.info(f"Server Response: {decoded_response}")

            client_socket.close()

        except Exception as exception:
            logger.error(f"Error sending message to the Server: {exception}")

    @staticmethod
    def arg_parser() -> tuple:
        """Parse command-line arguments and return the command and MAC address."""
        parser = argparse.ArgumentParser(description='Send commands to the server.')
        parser.add_argument('-a', metavar="mac", help='add MAC address to the server')
        parser.add_argument('-d', metavar="mac", help='delete MAC address from the server')

        res = parser.parse_args()
        if res.a is not None:
            cmd = "add"
            mac = res.a

        elif res.d is not None:
            cmd = "del"
            mac = res.d

        else:
            parser.print_help()
            sys.exit(1)

        if not CommandSender.is_valid_mac(mac):
            logger.warning("Invalid MAC address format. Please use the format: XX:XX:XX:XX:XX:XX")
            sys.exit(1)

        return cmd, mac

    def run(self) -> None:
        """Run the command sender, parsing arguments and sending commands to the server."""
        cmd, mac = CommandSender.arg_parser()
        command = {"cmd": cmd, "mac": mac}
        str_data = json.dumps(command)
        CommandSender.send_message_to_server(str_data)


sender = CommandSender()
sender.run()
