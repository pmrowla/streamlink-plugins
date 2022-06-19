# -*- coding: utf-8 -*-
"""eplus.jp streamlink plugin.

Requires direct ticketed stream/VOD URL (login via JP account currently
unsupported).
"""

import logging
import html
import random
import re
from time import time as get_timestamp_second
from threading import Thread, Event
from typing import List

from requests.cookies import RequestsCookieJar
from requests.exceptions import HTTPError
from streamlink.buffers import RingBuffer
from streamlink.exceptions import StreamError
from streamlink.plugin import Plugin
from streamlink.plugin.api import validate, useragents
from streamlink.stream.hls import HLSStream, HLSStreamReader, HLSStreamWorker, Sequence
from streamlink.stream.hls_playlist import M3U8

log = logging.getLogger(__name__)

# If the playlist keeps unchange for PLAYLIST_UNCHANGE_THRESHOLD_SEC, we consider the playlist ended.
PLAYLIST_UNCHANGE_THRESHOLD_SEC = 15

def _get_eplus_data(session, eplus_url):
    """Return video data for an eplus event/video page.

    URL should be in the form https://live.eplus.jp/ex/player?ib=<key>
    """
    result = {}
    body = session.http.get(eplus_url).text
    title = validate.Schema(
        validate.parse_html(),
        validate.xml_xpath_string(".//head/title/text()"),
    ).validate(body)
    result["title"] = html.unescape(title.strip())
    m = re.search(r"""var listChannels = \["(?P<channel_url>.*)"\]""", body)
    if m:
        result["channel_url"] = m.group("channel_url").replace(r"\/", "/")
    return result


class EplusSessionUpdater(Thread):
    def __init__(self, session, eplus_url):
        self._eplus_url = eplus_url
        self._session = session
        self._closed = Event()

        super().__init__(name='EplusSessionUpdater', daemon=True)

    def close(self):
        log.info('[EplusSessionUpdater] Closing...')
        self._closed.set()

    def run(self):
        while True:
            if self._closed.is_set():
                return

            # Create a new session, and send a request to Eplus url to obtain the cookies4
            log.debug('[EplusSessionUpdater] Refreshing cookies...')
            try:
                # TODO: Use another session to get the cookies, instead of using existing session.
                fresh_response = self._session.http.get(self._eplus_url, headers={
                    'Cookie': ''
                })

                # Update the session with the new cookies
                self._session.http.cookies.clear()
                self._session.http.cookies.update(fresh_response.cookies)
                log.debug(f'[EplusSessionUpdater] Successfully updated cookies: <{repr(fresh_response.cookies)}>')

            except Exception as e:
                # TODO: Retry refresh cookies
                log.error(f'[EplusSessionUpdater] Failed to refresh cookies: \n{e}')

            self.wait_for_about_half_hour()

    def wait_for_about_half_hour(self):
        """
        Cookie of the Eplus expires after about 1 hour.
        To keep the cookie fresh, we'll have to refresh the cookies every half hour.

        e.g. To avoid multiple people visiting Eplus at the same time, a random interval is used.
        """
        wait_sec = random.randint(20 * 60, 40 * 60)
        log.debug(f'[EplusSessionUpdater] Will update again after {wait_sec // 60}m {wait_sec % 60}s')
        self._closed.wait(wait_sec)


class EplusHLSStreamWorker(HLSStreamWorker):
    def __init__(self, *args, eplus_url=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._eplus_url = eplus_url
        self._first_playlist_unchanged = None

    def _reload_playlist_helper(self):
        try:
            log.debug('[EplusHLSStreamWorker] Reloading playlist...')
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

    def reload_playlist(self):
        reload_result = self._reload_playlist_helper()
        log.debug(f'[EplusHLSStreamWorker] Playlist reloaded. self.playlist_changed = {self.playlist_changed}, _first_playlist_unchanged = {self._first_playlist_unchanged}')

        if not self.playlist_changed:
            # If playlist unchanged, check if the stream is actually ended.
            current_time = get_timestamp_second()
            if self._first_playlist_unchanged is None:
                self._first_playlist_unchanged = current_time

            if current_time - self._first_playlist_unchanged > PLAYLIST_UNCHANGE_THRESHOLD_SEC:
                log.debug(f'[EplusHLSStreamWorker] Unchage threshold exceed. current_time = {current_time}, self._first_playlist_unchanged = {self._first_playlist_unchanged}')

                # The playlist won't change. Close the stream.
                self.close()
            else:
                log.debug(f'[EplusHLSStreamWorker] Playlist unchanged but threshold does not exceed. current_time = {current_time}, self._first_playlist_unchanged = {self._first_playlist_unchanged}')
        else:
            # If playlist changed, reset first_playlist_unchanged.
            if self._first_playlist_unchanged is not None:
                log.debug(f'[EplusHLSStreamWorker] Playlist changed. Reset _first_playlist_unchanged to None.')
            self._first_playlist_unchanged = None

        return reload_result


class EplusHLSStreamReader(HLSStreamReader):
    __worker__ = EplusHLSStreamWorker

    def __init__(self, *args, eplus_url=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._eplus_url = eplus_url
        self.session_updater = EplusSessionUpdater(session=self.session, eplus_url=eplus_url)

    def open(self):
        buffer_size = self.session.get_option("ringbuffer-size")
        self.buffer = RingBuffer(buffer_size)
        self.writer = self.__writer__(self)
        self.worker = self.__worker__(self, eplus_url=self._eplus_url)

        self.writer.start()
        self.worker.start()

        self.session_updater.start()

    def close(self):
        super().close()
        self.session_updater.close()


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
