import io
import os
import sys
import json
import socket
import signal
import threading
import logging
from tempfile import NamedTemporaryFile
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime
from target_manager import TargetManager
from configparser import ConfigParser
# from google.cloud import storage
from traffic_logger import logger_setup
from scapy.all import sniff, wrpcap, Ether, raw,  IP, UDP, TCP, srp, ARP
from config import SERVER_PORT, BUFFER_SIZE, INTERFACE, PACKETS_PER_FILE, TRAFFIC_DIRECTORY

logger_setup()
logger = logging.getLogger(__name__)


@dataclass
class Server:
    ip_address: str
    event: threading.Event
    target_manager: TargetManager
    shutdown_event: threading.Event = field(default_factory=threading.Event)
    data: Any = None
    running: bool = True
    pkt_count: int = 0

    def write(self, packet, mac_address):
        wrpcap(f'{TRAFFIC_DIRECTORY}/target{self.target_manager.macs[mac_address]}.pcap', packet, append = True)

    def packet_handler(self, packet):
        """
        Handle incoming network packets.

        This method is called for each packet captured by the packet sniffing process.
        It processes the packet to extract relevant information, checks if it contains
        IP layer and either UDP or TCP layer, and uploads the packet data to cloud storage
        if the source MAC address is in the target manager's list.

        Parameters:
        - packet: The network packet captured by the packet sniffing process.

        Returns:
        - None

        Behavior:
        1. Checks if the packet has an IP layer and either UDP or TCP layer.
        2. If the conditions are met, it extracts the source MAC address and IP address from the packet.
        3. Creates a dictionary with the source MAC address as the key and the source IP address as the value.
        4. Acquires a lock on the target manager to safely access and modify its data structures.
        5. Checks if the source MAC address is in the target manager's list of MAC addresses.
        6. If the conditions are met, increments the packet count and proceeds to upload the packet data to cloud storage.
        7. Logs the received packet data for informational purposes.
        """

        if packet.haslayer(IP) and (packet.haslayer(UDP) or packet.haslayer(TCP)):
            source_mac, source_ip = packet[Ether].src, packet[IP].src
            with self.target_manager.lock:
                if source_mac in self.target_manager.macs and self.pkt_count < int(PACKETS_PER_FILE):
                    logger.info(f"Received packet data: {source_mac}")
                    self.write(packet, source_mac)
                    self.pkt_count += 1
                

    def sniff_packets(self):
        sniff(prn=self.packet_handler, store=0, iface=INTERFACE)
        
        """
        Sniff network packets and handle them using the specified packet_handler.
        """

    def start_server(self, my_data):
        """
        Start a UDP server to handle incoming messages and process client commands.

        Binds the server socket to a specific IP address and port, then continuously
        listens for incoming messages. Messages are expected to be in JSON format.

        Args:
            my_data (str): Data to be passed to the server.
        """

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.ip_address, SERVER_PORT))
        logger.info("ENTER TARGET MAC ADDRESS TO MONITOR: ")

        while not self.shutdown_event.is_set():
            try:
                message, client_address = server_socket.recvfrom(BUFFER_SIZE)
                logger.info(f"Message from Client {client_address}: {message.decode()}")
                data = json.loads(message.decode())
                response_message = self.process_client_command(data)

                if response_message:
                    server_socket.sendto(response_message.encode(), client_address)

            except socket.error as e:
                logger.error(f"Socket error: {e}")

    def process_client_command(self, data):
        """
        Process a client command based on the provided data.

        Parses the 'cmd' and 'mac' fields from the given data dictionary and performs
        the corresponding action. Supported commands are 'add' and 'del', indicating
        the addition or removal of a target MAC address.

        Args:
            data (dict): A dictionary containing 'cmd' and 'mac' fields.

        Returns:
            str: Response message indicating the result of the command.
        """
        command = data.get("cmd")
        mac = data.get("mac")
        if command and mac:
            if command == "add":
                return self.target_manager.add_target(mac)
            elif command == "del":
                return self.target_manager.remove_target(mac)

        return "Invalid command. Please use 'add' or 'del'."

    def start(self):
        """
        Start the server and packet sniffer threads, and handle shutdown signals.

        Sets up signal handlers for termination and interruption, then launches
        server and sniffer threads in the background. Waits for threads to complete
        or until interrupted.
        """
        signal.signal(signal.SIGTERM, self.shutdown_handler)
        signal.signal(signal.SIGINT, self.shutdown_handler)

        server_thread = threading.Thread(target=self.start_server, args=(self.data,))
        server_thread.daemon = True
        server_thread.start()

        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()
        
        try:
            server_thread.join()
            sniff_thread.join()
        except KeyboardInterrupt:
            self.shutdown_handler(signal.SIGINT, None)

    def shutdown_handler(self, signum, frame):
        """
        Handle the shutdown of the application gracefully.

        Logs a shutdown message and sets the shutdown event to signal
        server and sniffer threads to terminate. Exits the application.
        """
        logger.info(f"Received signal {signal.Signals(signum).name}. Shutting down gracefully...")
        self.running = False
        self.shutdown_event.set()
        sys.exit(0)
