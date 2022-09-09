import asyncio
import json
import os
import os.path
import random
import re
import selectors
import socket
import sys
import time
import traceback
from asyncio import events
from contextlib import suppress
from functools import lru_cache
from itertools import cycle
from typing import List, Optional, Tuple, Union

import requests

from src.core import cl, CONFIG_URL, logger
from src.i18n import translate as t


# @formatter:off
print_exc_orig = traceback.print_exc
traceback.print_exc = lambda *args, **kwargs: None
import psutil
traceback.print_exc = print_exc_orig
# @formatter:on


IS_WINDOWS = sys.platform in {"win32", "cygwin"}
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform.startswith("darwin") or sys.platform.startswith("freebsd")

LINUX_DEFAULT_PORT_RANGE = (32_768, 61_000)
IANA_DEFAULT_PORT_RANGE = (49_152, 65_535)

WINDOWS_WAKEUP_SECONDS = 0.5


def fix_ulimits() -> Optional[int]:
    try:
        import resource
    except ImportError:
        return None

    min_limit = 2 ** 15
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    # Try to raise hard limit if it's too low
    if hard < min_limit:
        with suppress(ValueError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (min_limit, min_limit))
            soft = hard = min_limit

    # Try to raise soft limit to hard limit
    if soft < hard:
        with suppress(ValueError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard

    return soft


def _sync_fetch(url: str, timeout=10):
    try:
        response = requests.get(url, verify=False, timeout=timeout)
        response.raise_for_status()
        return response.content
    except requests.RequestException:
        return None


async def read_or_fetch(path_or_urls: Union[str, List[str]]) -> Optional[bytes]:
    if isinstance(path_or_urls, str) and os.path.exists(path_or_urls):
        with open(path_or_urls, 'rb') as f:
            return f.read()
    return await fetch(path_or_urls)


async def fetch(urls: Union[str, List[str]]) -> Optional[bytes]:
    if isinstance(urls, str):
        urls = [urls]

    urls = list(urls)
    random.shuffle(urls)

    min_retries = 3
    retries_per_url = 2
    retries = max(retries_per_url * len(urls), min_retries)
    for retry, url in zip(range(retries), cycle(urls)):
        loop = asyncio.get_running_loop()
        content = await loop.run_in_executor(None, _sync_fetch, url)
        if content:
            return content


async def load_system_configs():
    local_config = json.loads(await read_or_fetch('config.json'))
    remote_config = None
    remote_config_cnt = await fetch(CONFIG_URL)
    if remote_config_cnt:
        remote_config = json.loads(remote_config_cnt)
    else:
        logger.warning(f'{cl.MAGENTA}Failed to load remote config, a local copy will be used!{cl.RESET}')
    return local_config, remote_config


def _safe_connection_lost(transport, exc) -> None:
    try:
        transport._protocol.connection_lost(exc)
    finally:
        if hasattr(transport._sock, 'shutdown') and transport._sock.fileno() != -1:
            try:
                transport._sock.shutdown(socket.SHUT_RDWR)
            except ConnectionResetError:
                pass
        transport._sock.close()
        transport._sock = None
        server = transport._server
        if server is not None:
            server._detach()
            transport._server = None


def _patch_proactor_connection_lost() -> None:
    """
    The issue is described here:
      https://github.com/python/cpython/issues/87419

    The fix is going to be included into Python 3.11. This is merely
    a backport for already versions.
    """
    from asyncio.proactor_events import _ProactorBasePipeTransport

    setattr(_ProactorBasePipeTransport, "_call_connection_lost", _safe_connection_lost)


async def _windows_support_wakeup() -> None:
    """See more info here:
        https://bugs.python.org/issue23057#msg246316
    """
    while True:
        await asyncio.sleep(WINDOWS_WAKEUP_SECONDS)


def _handle_uncaught_exception(loop: asyncio.AbstractEventLoop, context) -> None:
    error_message = context.get("exception", context["message"])
    logger.debug(f"Uncaught event loop exception: {error_message}")


def setup_event_loop() -> asyncio.AbstractEventLoop:
    uvloop = False
    try:
        __import__("uvloop").install()
        uvloop = True
        logger.info(f"{t('`uvloop` activated successfully')} {t('(increased network efficiency)')}")
    except:
        pass

    if uvloop:
        loop = events.new_event_loop()
    elif IS_WINDOWS:
        _patch_proactor_connection_lost()
        loop = asyncio.ProactorEventLoop()
        # This is to allow CTRL-C to be detected in a timely fashion,
        # see: https://bugs.python.org/issue23057#msg246316
        loop.create_task(_windows_support_wakeup())
    elif hasattr(selectors, "DefaultSelector"):
        selector = selectors.DefaultSelector()
        loop = asyncio.SelectorEventLoop(selector)
    else:
        loop = events.new_event_loop()
    loop.set_exception_handler(_handle_uncaught_exception)
    asyncio.set_event_loop(loop)
    return loop


def _detect_port_range() -> Optional[Tuple[int, int]]:
    if IS_LINUX:
        try:
            with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
                low, high = f.read().split()
            return int(low), int(high)
        except Exception:
            return LINUX_DEFAULT_PORT_RANGE

    if IS_MACOS:
        try:
            ctl = "sysctl -n net.inet.ip.portrange.first net.inet.ip.portrange.last"
            with os.popen(ctl) as f:
                low, high = f.readlines()
            return int(low), int(high)
        except Exception:
            return IANA_DEFAULT_PORT_RANGE

    if IS_WINDOWS:
        try:
            ctl = "netsh int ipv4 show dynamicport tcp"
            with os.popen(ctl) as f:
                low, ports = re.findall(r"\d+", f.read())
            return int(low), int(low) + int(ports)
        except Exception:
            return IANA_DEFAULT_PORT_RANGE


@lru_cache(maxsize=None)
def detect_port_range_size() -> int:
    try:
        low, high = _detect_port_range()
    except Exception:
        low, high = IANA_DEFAULT_PORT_RANGE  # IANA default
    return max(high - low + 1, 1024)  # Be safe and never return less then 1024


@lru_cache(maxsize=None)
def detect_local_iface() -> Optional[str]:
    with suppress(Exception):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            laddr, _ = sock.getsockname()
        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == laddr:
                    return iface_name
    return None


def fetch_netstats(iface: Optional[str]) -> Optional['psutil._common.snetio']:
    with suppress(Exception):
        if not iface is None:
            res = psutil.net_io_counters(pernic=True).get(iface, None)
            if res is None:
                res = psutil.net_io_counters()
        else:
            res = psutil.net_io_counters()
        return res
    return None


class NetStats:

    def __init__(self):
        self._iface = detect_local_iface()
        self._timer = time.perf_counter()
        self._cursor = fetch_netstats(self._iface)

    def tick(self) -> Optional[Tuple[float, float]]:
        if self._cursor is None:
            return None
        now = time.perf_counter()
        next_cursor = fetch_netstats(self._iface)
        elapsed = now - self._timer
        diff = (
            (next_cursor.packets_sent - self._cursor.packets_sent) / elapsed,
            (next_cursor.bytes_sent - self._cursor.bytes_sent) / elapsed,
        )
        self._timer = now
        self._cursor = next_cursor
        return diff
