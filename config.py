SERVER_PORT = 80
LOOPBACK_ADDRESS = '0.0.0.0'
INTERFACE = 'eno1' # Input the network interface of the machine
BUFFER_SIZE = 1024 
PACKETS_PER_FILE = '100' # The sniffer won't capture more packets when it reaches this ammount
TRAFFIC_DIRECTORY = 'traffic' # .The pcap files of the targets will be stored here 