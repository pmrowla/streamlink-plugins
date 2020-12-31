# -*- coding: utf-8 -*-
"""eplus.jp streamlink plugin.

Requires direct ticketed stream/VOD URL (login via JP account currently
unsupported).
"""

import logging
import re
from base64 import b64decode
from urllib.parse import unquote_plus

from streamlink.plugin import Plugin
from streamlink.plugin.api import useragents
from streamlink.plugin.api.utils import itertags
from streamlink.stream import HLSStream

log = logging.getLogger(__name__)


class Eplus(Plugin):

    # https://live.eplus.jp/ex/player?ib=<key>
    # key is base64-encoded 64 byte unique key per ticket
    _URL_RE = re.compile(r"https://live\.eplus\.jp/ex/player\?ib=.+")
    _ORIGIN = "https://live.eplus.jp"
    _REFERER = "https://live.eplus.jp/"

    def __init__(self, url):
        super().__init__(url)
        self.session.http.headers.update({
            "Origin": self._ORIGIN,
            "Referer": self._REFERER,
            "User-Agent": useragents.CHROME,
        })
        self.title = None

    @classmethod
    def can_handle_url(cls, url):
        return cls._URL_RE.match(url) is not None

    def get_title(self):
        return self.title

    def _get_streams(self):
        body = self.session.http.get(self.url).text
        for title in itertags(body, "title"):
            self.title = title.text.strip()
            break

        m = re.search(r"""var listChannels = \["(?P<channel_url>.*)"\]""", body)
        if m:
            channel_url = m.group("channel_url").replace(r"\/", "/")
            if channel_url:
                yield from HLSStream.parse_variant_playlist(self.session, channel_url).items()


__plugin__ = Eplus
