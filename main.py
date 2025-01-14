import logging
import server
import os
from config import LOOPBACK_ADDRESS
from target_manager import TargetManager
from threading import Thread, Event
from traffic_logger import logger_setup

logger_setup()
logger = logging.getLogger(__name__)

event = Event()

if __name__ == "__main__":
    target_manager_instance = TargetManager()
    server = server.Server(LOOPBACK_ADDRESS, event, target_manager_instance)
    server.start()
    
