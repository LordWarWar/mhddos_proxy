import logging
import os
import sys
import warnings
from asyncio.log import logger as asyncio_logger
from multiprocessing import cpu_count
from pathlib import Path
from typing import Set

from colorama import Fore


warnings.filterwarnings("ignore")


class RemoveUselessWarnings(logging.Filter):
    def filter(self, record):
        return all((
            "socket.send() raised exception." not in record.getMessage(),
            "SSL connection is closed" not in record.getMessage()
        ))


LOGGER_MSG_FORMAT = '[%(asctime)s - %(levelname)s] %(message)s'
LOGGER_DATE_FORMAT = "%H:%M:%S"

logging.basicConfig(format=LOGGER_MSG_FORMAT, datefmt=LOGGER_DATE_FORMAT)
logger = logging.getLogger('mhddos_proxy')
logger.setLevel('INFO')

# Make asyncio logger a little bit less noisy
asyncio_logger.addFilter(RemoveUselessWarnings())


def setup_worker_logging(process_index: int) -> None:
    if process_index > 0:
        logger.setLevel(logging.ERROR)
        sys.stdout = open(os.devnull, 'w')


ROOT_DIR = Path(__file__).parent.parent

CONFIG_URL = "https://raw.githubusercontent.com/LordWarWar/mhddos_proxy/main/config.json"

CPU_COUNT = cpu_count()
DEFAULT_THREADS = 8000 if CPU_COUNT > 1 else 4000
LIMITS_PADDING = 50

COPIES_AUTO = "auto"
MAX_COPIES_AUTO = 4

USE_ONLY_MY_IP = 100
SCHEDULER_INITIAL_CAPACITY = 3
SCHEDULER_MIN_INIT_FRACTION = 0.15
SCHEDULER_MAX_INIT_FRACTION = 0.5
SCHEDULER_FORK_SCALE = 6
CONN_PROBE_PERIOD = 5
PROXY_ALIVE_PRIO_THRESHOLD = 0.25
PROXY_ALIVE_PRIO_RATE = 0.5

UDP_FAILURE_BUDGET_FACTOR = 3
UDP_FAILURE_DELAY_SECONDS = 1
UDP_BATCH_PACKETS = 16
UDP_ENOBUFS_PAUSE = 0.5

IS_AUTO_MH = os.getenv('AUTO_MH')
IS_DOCKER = os.getenv('IS_DOCKER')


class cl:
    MAGENTA = Fore.LIGHTMAGENTA_EX
    CYAN = Fore.LIGHTCYAN_EX
    BLUE = Fore.LIGHTBLUE_EX
    GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    RED = Fore.LIGHTRED_EX
    RESET = Fore.RESET


class Methods:
    HTTP_METHODS: Set[str] = {
        "CFB", "BYPASS", "HTTP_TEMPLATE", "GET", "RGET", "HEAD", "RHEAD", "POST", "STRESS", "DYN", "SLOW",
        "NULL", "COOKIE", "PPS", "EVEN", "AVB",
        "APACHE", "XMLRPC", "DOWNLOADER", "RHEX", "STOMP", "GOSPASS",
        # this is not HTTP method (rather TCP) but this way it works with --http-methods
        # settings being applied to the entire set of targets
        "TREX",
    }
    TCP_METHODS: Set[str] = {"TCP", }
    UDP_METHODS: Set[str] = {
        "UDP", "VSE", "FIVEM", "TS3", "MCPE",
        # the following methods are temporarily disabled for further investigation and testing
        # "SYN", "CPS",
        # Amplification
        # "ARD", "CHAR", "RDP", "CLDAP", "MEM", "DNS", "NTP"
    }
    ALL_METHODS: Set[str] = {*HTTP_METHODS, *UDP_METHODS, *TCP_METHODS}
