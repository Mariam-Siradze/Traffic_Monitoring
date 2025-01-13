import os
import shutil
import threading
from dataclasses import dataclass, field
from config import TRAFFIC_DIRECTORY


@dataclass
class TargetManager:
    """
    Manages a set of target MAC addresses and their associated directories.

    Attributes:
        macs (set): Set of target MAC addresses.
        mac_directories (dict): Dictionary mapping MAC addresses to their corresponding directories.
        lock (threading.Lock): Thread lock for ensuring thread safety.

    Methods:
        add_target(mac: str) -> str: Add a target MAC address to the manager.
        remove_target(mac: str) -> str: Remove a target MAC address from the manager.
        get_targets() -> List[str]: Get a list of current target MAC addresses.
    """

    macs: dict = field(default_factory=dict)
    mac_dir: str = os.path.join(os.getcwd(), TRAFFIC_DIRECTORY)
    lock: threading.Lock = field(default_factory=threading.Lock)
    target_count: int = 0

    def __post_init__(self):
        if os.path.isdir(self.mac_dir):
            shutil.rmtree(self.mac_dir)

    def add_target(self, mac: str) -> str:
        """
        Add a target MAC address to the manager.

        Args:
            mac (str): The MAC address to be added.

        Returns:
            str: A message indicating the success or failure of the operation.                                                                                                      
        """
        with self.lock:
            if mac not in self.macs:
                self.target_count += 1
                self.macs[mac] = self.target_count
                os.makedirs(self.mac_dir, exist_ok=True)
                return f"MAC {mac} successfully added."
            else:
                return f"MAC {mac} already exists."

    def remove_target(self, mac: str) -> str:
        """
        Remove a target MAC address from the manager.

        Args:
            mac (str): The MAC address to be removed.

        Returns:
            str: A message indicating the success or failure of the operation.
        """
        with self.lock:
            if mac in self.macs:
                os.remove(f'{self.mac_dir}/target{self.macs[mac]}.pcap')
                self.macs.pop(mac)
                return f"MAC {mac} successfully removed."
            else:
                return f"MAC {mac} not found in the list."

    def get_targets(self) -> list:
        """
        Get a list of current target MAC addresses.

        Returns:
            List[str]: A list of target MAC addresses.
        """
        with self.lock:
            return list(self.macs)
