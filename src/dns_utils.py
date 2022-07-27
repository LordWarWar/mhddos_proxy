import asyncio
from asyncio import gather
from typing import Dict, List, Optional

import dns.exception
from asyncstdlib.functools import lru_cache
from dns.asyncresolver import Resolver
from dns.resolver import NoResolverConfiguration

from .core import cl, logger
from .exclude import is_forbidden_ip
from .i18n import translate as t


try:
    resolver = Resolver(configure=True)
except NoResolverConfiguration:
    resolver = Resolver(configure=False)

ns = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '208.67.222.222', '208.67.220.220']
resolver.nameservers = ns + list(resolver.nameservers)

RESOLVER_MAX_CONCURRENT = 100


@lru_cache(maxsize=1024)
async def _resolve_host(host: str) -> str:
    if dns.inet.is_address(host):
        return host
    answer = await resolver.resolve(host)
    return answer[0].to_text()


async def _safe_resolve_host(host: str, semaphore: asyncio.Semaphore) -> Optional[str]:
    try:
        async with semaphore:
            resolved = await _resolve_host(host)
        if is_forbidden_ip(resolved):
            raise dns.exception.DNSException("resolved to unsupported address")
        return resolved
    except dns.exception.DNSException:
        logger.warning(
            f"{cl.MAGENTA}{t('Target')} {cl.BLUE}{host}{cl.MAGENTA}"
            f""" {t("is not available and won't be attacked")}{cl.RESET}"""
        )


async def resolve_all(hosts: List[str]) -> Dict[str, str]:
    unresolved_hosts = list(set(
        host
        for host in hosts
        if not dns.inet.is_address(host)
    ))
    semaphore = asyncio.Semaphore(RESOLVER_MAX_CONCURRENT)
    answers = await gather(*[
        _safe_resolve_host(h, semaphore)
        for h in unresolved_hosts
    ])
    ips = dict(zip(unresolved_hosts, answers))
    return {
        host: ips.get(host, host)
        for host in hosts
    }


async def resolve_all_targets(targets: List["Target"]) -> List["Target"]:
    unresolved_hosts = list(set(
        target.url.host
        for target in targets
        if not target.is_resolved
    ))
    ips = await resolve_all(unresolved_hosts)
    for target in targets:
        if not target.is_resolved:
            target.addr = ips.get(target.url.host)
    return targets
