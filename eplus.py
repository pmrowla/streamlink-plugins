# -*- coding: utf-8 -*-
"""eplus.jp streamlink plugin.

Requires direct ticketed stream/VOD URL (login via JP account currently
unsupported).
"""

import logging
import html
import re
import time

from requests.exceptions import HTTPError
from streamlink.buffers import RingBuffer
from streamlink.exceptions import StreamError
from streamlink.plugin import Plugin
from streamlink.plugin.api import useragents
from streamlink.plugin.api.utils import itertags
from streamlink.stream.hls import HLSStream, HLSStreamReader, HLSStreamWorker

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


class EplusHLSStreamWorker(HLSStreamWorker):
    def __init__(self, *args, eplus_url=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._eplus_url = eplus_url

    def reload_playlist(self):
        try:
            return super().reload_playlist()
        except StreamError as err:
            rerr = getattr(err, "err", None)
            if (
                self._eplus_url
                and rerr is not None
                and isinstance(rerr, HTTPError)
                and rerr.response.status_code == 403
            ):
                log.debug("eplus auth rejected, refreshing session")
                self.session.http.get(
                    self._eplus_url,
                    exception=StreamError,
                    **self.reader.request_params,
                )
            else:
                raise
        return super().reload_playlist()


class EplusHLSStreamReader(HLSStreamReader):
    __worker__ = EplusHLSStreamWorker

    def __init__(self, *args, eplus_url=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._eplus_url = eplus_url

    def open(self):
        buffer_size = self.session.get_option("ringbuffer-size")
        self.buffer = RingBuffer(buffer_size)
        self.writer = self.__writer__(self)
        self.worker = self.__worker__(self, eplus_url=self._eplus_url)

        self.writer.start()
        self.worker.start()


class EplusHLSStream(HLSStream):
    __reader__ = EplusHLSStreamReader

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eplus_url = None

    def open(self):
        reader = self.__reader__(self, eplus_url=self.eplus_url)
        reader.open()

        return reader


class Eplus(Plugin):

    # https://live.eplus.jp/ex/player?ib=<key>
    # key is base64-encoded 64 byte unique key per ticket
    _URL_RE = re.compile(r"https://live\.eplus\.jp/ex/player\?ib=.+")
    _ORIGIN = "https://live.eplus.jp"
    _REFERER = "https://live.eplus.jp/"

    def __init__(self, url):
        super().__init__(url)
        self.session.http.headers.update(
            {
                "Origin": self._ORIGIN,
                "Referer": self._REFERER,
                "User-Agent": useragents.CHROME,
            }
        )
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
            for name, stream in EplusHLSStream.parse_variant_playlist(
                self.session, channel_url
            ).items():
                stream.eplus_url = self.url
                yield name, stream


__plugin__ = Eplus
