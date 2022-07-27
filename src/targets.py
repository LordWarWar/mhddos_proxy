import base64
import json
import geocoder
from typing import Dict, Optional, Set

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from dns import inet
from yarl import URL

from .core import cl, logger, Methods
from .dns_utils import resolve_all_targets
from .i18n import translate as t
from .system import read_or_fetch


Options = Dict[str, str]


class Target:
    __slots__ = ['url', 'method', 'options', 'addr', 'hash', 'cache']

    def __init__(
        self,
        url: URL,
        method: Optional[str] = None,
        options: Optional[Options] = None,
        addr: Optional[str] = None
    ):
        if method and method not in Methods.ALL_METHODS:
            raise ValueError(f'Invalid method {method}')

        self.url = url
        self.method = method
        self.options = options or {}
        self.addr = self.option("ip", addr)

        options_str = json.dumps(self.options, sort_keys=True)
        self.hash = hash((self.url, self.method, options_str, self.addr))

        self.cache = {}  # In case you want to cache something per-target, like templates

    def __eq__(self, other):
        return self.hash == other.hash

    def __hash__(self):
        return self.hash

    @classmethod
    def from_string(cls, raw: str) -> "Target":
        parts = [part.strip() for part in raw.split(" ")]
        n_parts = len(parts)
        url = URL(cls.prepare_url(parts[0]))

        method = None
        if n_parts > 1:
            method = parts[1].upper()

        addr = url.host if inet.is_address(url.host) else None
        return cls(url, method, {}, addr)

    @classmethod
    def from_dict(cls, raw: dict) -> "Target":
        url = URL(cls.prepare_url(raw['target']))
        return Target(
            url=url,
            method=raw.get('method'),
            addr=raw.get('ip'),
            options=raw.get('options'),
        )

    @staticmethod
    def prepare_url(target: str) -> str:
        if '://' in target:
            return target

        try:
            _, port = target.split(':', 1)
        except ValueError:
            port = '80'

        scheme = 'https://' if port == '443' else 'http://'
        return scheme + target

    @property
    def is_resolved(self) -> bool:
        if self.addr!=None:
            if geocoder.ip(self.addr).country=="UA": return None
        return self.addr is not None

    @property
    def is_udp(self) -> bool:
        return self.url.scheme == "udp"

    def option(self, key: str, default: Optional[object] = None) -> Optional[object]:
        return self.options.get(key, default)

    @property
    def has_options(self) -> bool:
        return len(self.options) > 0


ENC_KEYS = {
    b'\xe4\xdc\xf7\x1f': b'fZPK2OTLiNdqVDBxJTSMuph/rfLzpFWHDmHC1/+rR1s=',
}


class TargetsLoader:
    def __init__(self, targets, targets_config, global_config, it_army: bool = False):
        self._targets = [Target.from_string(raw) for raw in targets]
        self._cmd_targets_config = targets_config
        self._global_config = global_config
        self._it_army = it_army

    async def reload(self) -> Set[Target]:
        config_targets = await self._load_config()
        if config_targets:
            logger.info(
                f"{cl.YELLOW}{t('Loaded config for')} {cl.BLUE}{len(config_targets)} {t('targets')}{cl.RESET}"
            )

        all_targets = await resolve_all_targets(self._targets + config_targets)
        all_targets = set(target for target in all_targets if target.is_resolved)
        return all_targets

    async def _load_config(self):
        if self._it_army:
            target_urls = self._global_config['it_army_config_urls_list']
        elif self._cmd_targets_config:
            target_urls = self._cmd_targets_config  # do not make a list, so local path can be handled by read_or_fetch
        else:
            return []

        content = await read_or_fetch(target_urls)
        if content is None:
            raise RuntimeError('Failed to load configuration')

        content = self._possibly_decrypt(content).decode()
        targets = []

        try:
            data = json.loads(content)
            for config in data['targets']:
                try:
                    targets.append(Target.from_dict(config))
                except Exception as exc:
                    logger.warning(f'{cl.MAGENTA}Failed to parse {config} ({exc}){cl.RESET}')

        except json.JSONDecodeError:
            for row in content.splitlines():
                target = row.strip()
                if target and not target.startswith('#'):
                    try:
                        targets.append(Target.from_string(target))
                    except Exception as exc:
                        logger.warning(f'{cl.MAGENTA}Failed to parse {target} ({exc}){cl.RESET}')

        return targets

    def _possibly_decrypt(self, content):
        nonce_len = 12
        for version, key in ENC_KEYS.items():
            if content.startswith(version):
                v_len = len(version)
                cip = ChaCha20Poly1305(key=base64.b64decode(key))
                nonce = content[v_len: v_len + nonce_len]
                return cip.decrypt(nonce, content[v_len + nonce_len:], None)
        return content
