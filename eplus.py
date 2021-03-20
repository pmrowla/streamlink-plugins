# -*- coding: utf-8 -*-
"""eplus.jp streamlink plugin.

Requires direct ticketed stream/VOD URL (login via JP account currently
unsupported).
"""

import logging
import html
import re
import time

from streamlink.exceptions import StreamError
from streamlink.plugin import Plugin
from streamlink.plugin.api import useragents
from streamlink.plugin.api.utils import itertags
from streamlink.stream import HLSStream

log = logging.getLogger(__name__)


def _get_eplus_data(session, eplus_url):
    """Return video data for an eplus event/video page.

    URL should be in the form https://live.eplus.jp/ex/player?ib=<key>
    """
    result = {}
    body = session.http.get(eplus_url).text
    for title in itertags(body, "title"):
        result["title"] = html.unescape(title.text.strip())
        break
    m = re.search(r"""var listChannels = \["(?P<channel_url>.*)"\]""", body)
    if m:
        result["channel_url"] = m.group("channel_url").replace(r"\/", "/")
    return result


class EplusHLSStream(HLSStream):
    DEFAULT_TIMEOUT = 60 * 60

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eplus_url = None
        self.quality = None
        self.timeout = time.time() + self.DEFAULT_TIMEOUT

    @property
    def url(self):
        assert self.eplus_url and self.quality
        curtime = time.time()
        if curtime >= self.timeout:
            channel_url = _get_eplus_data(self.session, self.eplus_url).get("channel_url")
            if channel_url:
                stream = EplusHLSStream.parse_variant_playlist(self.session, channel_url)[self.quality]
                self.args.update(stream.args)
                self.timeout = curtime + self.DEFAULT_TIMEOUT
            else:
                raise StreamError("failed to refresh eplus channel url")
        return super().url


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
        data = _get_eplus_data(self.session, self.url)
        self.title = data.get("title")
        channel_url = data.get("channel_url")
        if channel_url:
            for name, stream in EplusHLSStream.parse_variant_playlist(self.session, channel_url).items():
                stream.eplus_url = self.url
                stream.quality = name
                yield name, stream


__plugin__ = Eplus
