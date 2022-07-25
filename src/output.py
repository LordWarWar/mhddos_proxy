from typing import Optional, Tuple

from .core import cl, CPU_COUNT, DEFAULT_THREADS, logger, USE_ONLY_MY_IP
from .i18n import translate as t
from .system import NetStats
from .utils import Tools


def show_statistic(
    net_stats: Optional[NetStats],
    flooders: Optional[Tuple[int, int]],
    num_connections: int
):
    netdiff = net_stats.tick()
    if netdiff is not None:
        total_pps, total_bps = netdiff
        total_pps = f"{Tools.humanformat(total_pps)}/s"
        total_bps = f"{Tools.humanbits(total_bps * 8)}/s"
    else:
        total_pps, total_bps = "n/a", "n/a"

    capacity = "n/a"
    if flooders:
        cur_cap, max_cap = flooders
        capacity = f"{100 * cur_cap / max_cap:.1f}%"

    logger.info(
        f"{cl.GREEN}{t('Total')}: "
        f"{cl.YELLOW}{t('Capacity')}:{cl.GREEN} {capacity}, "
        f"{cl.YELLOW}{t('Connections')}:{cl.GREEN} {num_connections}, "
        f"{cl.YELLOW}{t('Packets')}:{cl.GREEN} {total_pps}, "
        f"{cl.YELLOW}{t('Traffic')}:{cl.GREEN} {total_bps}{cl.RESET}"
    )


def print_status(
    threads: int,
    copies: int,
    use_my_ip: int,
    overtime: bool,
):
    if not use_my_ip:
        proxies_message = t('Using only proxies')
    elif use_my_ip == USE_ONLY_MY_IP:
        proxies_message = t('Using only your IP/VPN (no proxies)')
    else:
        proxies_message = t('Using both proxies and your IP/VPN')

    if copies > 1:
        threads_text = f'{copies * threads} ({copies} x {threads})'
    else:
        threads_text = str(threads)

    logger.info(
        f"{cl.YELLOW}{t('Threads')}: {cl.BLUE}{threads_text} | "
        f"{cl.MAGENTA}{proxies_message}{cl.RESET}"
    )

    if overtime:
        logger.warning(
            f"{cl.MAGENTA}{t('Delay in execution of operations detected')} - "
            f"{t('the attack continues, but we recommend reducing the workload')} `-t`{cl.RESET}"
        )
    print()


def print_banner(args):
    rows = []
    if not args.lang:
        rows.append(
            f"- {cl.YELLOW}Change language:{cl.BLUE} `--lang en` / `--lang es`{cl.RESET}"
        )
    if not args.threads:
        rows.append(
            f"- {cl.YELLOW}{t('Workload (number of threads)')}:{cl.BLUE} {t('use flag `-t XXXX`, default is')} "
            f"{DEFAULT_THREADS}"
        )
    elif args.threads > 10000 and args.copies == 1 and CPU_COUNT > 2:
        rows.append(
            f"- {cl.CYAN}{t('Instead of high `-t` value consider using')} {cl.YELLOW}`--copies 2`{cl.RESET}"
        )
    if not args.use_my_ip:
        rows.append(
            f"- {cl.MAGENTA}{t('Consider adding your IP/VPN to the attack - use flag `--vpn`')}{cl.RESET}"
        )
    rows.append(
        f"- {cl.YELLOW}{t('Complete documentation')}:{cl.RESET} - "
        f"https://github.com/LordWarWar/mhddos_proxy"
    )

    print()
    print(*rows, sep='\n')
    print()
