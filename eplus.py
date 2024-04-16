# -*- coding: utf-8 -*-
"""eplus.jp streamlink plugin.

Requires stream/VOD URL.
"""

import logging
import re
import time
from threading import Thread, Event
from typing import Dict, List
from urllib.parse import urlencode

from streamlink.exceptions import NoStreamsError, PluginError
from streamlink.plugin import Plugin, pluginargument, pluginmatcher
from streamlink.plugin.api import validate, useragents
from streamlink.session.http import HTTPSession
from streamlink.stream.hls import HLSStream, HLSStreamReader, HLSStreamWorker

log = logging.getLogger(__name__)


def _get_eplus_data(session: HTTPSession, eplus_url: str):
    """
    Return video data for an eplus event/video page.
    """
    schema_data_json = validate.Schema(
        re.compile(r"<script>\s*var\s+app\s*=\s*(?P<data_json>\{.+?\});\s*</script>"),
        validate.none_or_all(
            validate.get("data_json"),
            validate.parse_json(),
            {
                "delivery_status": str,
                "archive_mode": str,
                "app_id": str,
                "app_name": str,
                validate.optional("drm_mode"): validate.any(str, None),
            },
        ),
    )
    schema_m3u8_urls = validate.Schema(
        re.compile(r"var\s+listChannels\s*=\s*(?P<list_channels>\[.+?\]);"),
        validate.none_or_all(
            validate.get("list_channels"),
            validate.parse_json(),
            list,
        ),
    )
    schema_stream_session = validate.Schema(
        re.compile(r"var\s+streamSession\s*=\s*(['\"])(?P<stream_session>(?:(?!\1).)+)\1;"),
        validate.none_or_all(
            validate.get("stream_session"),
        ),
    )

    body = session.get(eplus_url).text

    data_json = schema_data_json.validate(body, "data_json")
    if not data_json:
        raise PluginError("Failed to get data_json")

    if data_json.get("drm_mode") == "ON":
        raise PluginError("Stream is DRM-protected")

    delivery_status = data_json["delivery_status"]
    archive_mode = data_json["archive_mode"]
    log.debug(f"delivery_status = {delivery_status}, archive_mode = {archive_mode}")

    if delivery_status == "PREPARING":
        log.error("This event has not started yet")
        raise NoStreamsError(eplus_url)
    elif delivery_status == "STARTED":
        pass  # is live
    elif delivery_status == "STOPPED":
        if archive_mode == "ON":
            log.error("This event has ended, but the archive has not been generated yet")
        else:
            log.error("This event has ended and there is no archive for this event")
        raise NoStreamsError(eplus_url)
    elif delivery_status == "WAIT_CONFIRM_ARCHIVED":
        log.error("This event has ended, and the archive will be available shortly")
        raise NoStreamsError(eplus_url)
    elif delivery_status == "CONFIRMED_ARCHIVE":
        pass  # was live
    else:
        raise PluginError(f"Unknown delivery_status: {delivery_status}")

    m3u8_urls = schema_m3u8_urls.validate(body, "m3u8 urls") or []

    app_id = data_json["app_id"]

    stream_session = schema_stream_session.validate(body, "stream_session")
    if stream_session:
        session_update_url = f"https://live.eplus.jp/api/stream/{app_id}/status?sid={stream_session}"
    else:
        session_update_url = ""

    return {
        "app_id": app_id,
        "title": data_json["app_name"],
        "m3u8_urls": m3u8_urls,
        "session_update_url": session_update_url,
    }


def _try_login(session: HTTPSession, eplus_url: str, login_id: str, password: str):
    log.info("Getting auth status")

    res = session.get(eplus_url)
    if res.url.startswith(eplus_url):
        # already logged in or no login required
        return

    auth_url = res.url

    cltft_token = res.headers.get("X-CLTFT-Token")
    if not cltft_token:
        raise PluginError("Unable to get X-CLTFT-Token for login")

    session.cookies.set("X-CLTFT-Token", cltft_token, domain="live.eplus.jp")

    if not all((login_id, password)):
        raise PluginError("Login credentials required")

    log.info("Sending pre-login info")

    login_res = session.post(
        "https://live.eplus.jp/member/api/v1/FTAuth/idpw", headers={
            "Content-Type": "application/json; charset=UTF-8",
            "Referer": auth_url,
            "X-Cltft-Token": cltft_token,
            "Accept": "*/*",
        }, json={
            "loginId": login_id,
            "loginPassword": password,
        })
    login_json = session.json(login_res, "login response")

    if not login_json.get("isSuccess"):
        raise PluginError("Login failed: Invalid id or password")

    log.info("Logging in via provided id and password")

    session.post(
        auth_url, data=urlencode({
            "loginId": id,
            "loginPassword": password,
            "Token.Default": cltft_token,
            "op": "nextPage",
        }), headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": res.url,
        })


class EplusData:
    @property
    def app_id(self) -> str:
        return self._data["app_id"]

    @property
    def title(self) -> str:
        return self._data["title"]

    @property
    def m3u8_urls(self) -> List[str]:
        return self._data["m3u8_urls"]

    @property
    def session_update_url(self) -> str:
        return self._data["session_update_url"]

    def __init__(self, session: HTTPSession, eplus_url: str, login_id: str, password: str, allow_relogin: bool):
        self._session = session
        self._eplus_url = eplus_url
        self._login_id = login_id
        self._password = password
        self._allow_relogin = allow_relogin

        self.login_and_refresh()

    def login_and_refresh(self):
        _try_login(self._session, self._eplus_url, self._login_id, self._password)
        self._data = _get_eplus_data(self._session, self._eplus_url)


class EplusSessionUpdater(Thread):
    """
    Cookies for Eplus expire after about 1 hour.
    To keep our live streaming going, we have to refresh them in time,
    otherwise we may got HTTP 403 and no new stream could be downloaded.
    """

    def __init__(self, session: HTTPSession, eplus_data: EplusData):
        super().__init__(name=self.__class__.__qualname__, daemon=True)

        self._session = session
        self._closed = Event()
        self._retries = 0
        self._last_expire_timestamp = time.time()
        self._log = logging.getLogger(f"{__name__}.{self.__class__.__qualname__}")

        self._eplus_data = eplus_data
        self._session_update_url = self._eplus_data.session_update_url
        # Sometimes the previously obtained stream session is invalid, so we need to try again unconditionally.
        self._never_valid_session = True

    def close(self):
        if self._closed.is_set():
            """
            "close(self)" will be called multiple times during the cleanup process of Streamlink.
            If Python is about to exit, logging something will raise an exception:
            > ImportError: sys.meta_path is None, Python is likely shutting down <
            """
            return

        self._log.debug("Closing session updater...")
        self._closed.set()

    def run(self):
        self._log.debug("Starting session updater...")

        while not self._closed.is_set():

            # Create a new session without cookies and send a request to Eplus url to obtain new cookies.
            self._log.debug(f"Refreshing cookies with url: {self._session_update_url}")
            try:
                fresh_response = self._session_duplicator().get(self._session_update_url)
                self._log.debug(f"Got new cookies: {fresh_response.cookies!r}")

                # Filter cookies.
                # For now, only the "ci_session" cookie is what we don't need, so ignore it.
                cookie = next(
                    cookie for cookie in fresh_response.cookies
                        if cookie.name != "ci_session"
                        and cookie.expires > time.time()
                )
                self._log.debug(
                    "Found a valid cookie that will expire at "
                    f"{time.strftime(r'%Y%m%d-%H%M%S%z', time.localtime(cookie.expires))}. "
                    f"The cookie: {cookie!r}"
                )

                # Update the global session with the new cookies.
                self._session.cookies.clear()
                self._session.cookies.update(fresh_response.cookies)

                self._retries = 0
                self._last_expire_timestamp = cookie.expires
                self._never_valid_session = False

                # Refresh cookies at most 5 minutes before expiration.
                wait_sec = (cookie.expires - 5 * 60) - time.time()
                # Don't be too close! Retry it right away.
                wait_sec = max(wait_sec, 0)
                # Eplus refreshes cookies every 15 minutes.
                wait_sec = min(15 * 60, wait_sec)

                self._log.debug(
                    "Refreshed cookies. Next attempt will be at about "
                    f"{time.strftime(r'%Y%m%d-%H%M%S%z', time.localtime(time.time() + wait_sec))}. "
                )

                self._closed.wait(wait_sec)
                continue

            except StopIteration:
                # next() exhausted all cookies.
                self._log.error("No valid cookies found.")

                # Re-login may help
                if self._never_valid_session or self._eplus_data._allow_relogin:
                    self._log.info("Trying to refresh the session. Any existing sessions will be kicked.")
                    try:
                        self._eplus_data.login_and_refresh()
                        self._session_update_url = self._eplus_data.session_update_url
                    except Exception as e:
                        self._log.error(f"Failed to refresh session: {e!r}")
                else:
                    self._log.info("The session will not be refreshed since re-login is disabled.")

            except Exception as e:
                self._log.error(f"Failed to refresh cookies: {e!r}")

            self._retries += 1
            retry_delay_sec = 2 ** (self._retries - 1)

            if time.time() + retry_delay_sec > self._last_expire_timestamp + 1 * 60 * 60:
                self._log.error("We have not refreshed cookies in the past hour and will not try again.")

                self.close()
                return

            self._log.debug(f"We will retry in {retry_delay_sec}s.")

            self._closed.wait(retry_delay_sec)
            continue

    def _session_duplicator(self):
        """
        Make a duplicate of the member "_session" except for cookies.
        """

        new_session = HTTPSession()

        new_session.proxies = self._session.proxies
        new_session.headers = self._session.headers
        new_session.trust_env = self._session.trust_env
        new_session.verify = self._session.verify
        new_session.cert = self._session.cert
        new_session.timeout = self._session.timeout

        return new_session
    
    @classmethod
    def make(cls, session: HTTPSession, eplus_data: EplusData):
        if eplus_data.session_update_url:
            return cls(session, eplus_data)
        else:
            return None


class EplusHLSStreamWorker(HLSStreamWorker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._log = logging.getLogger(f"{__name__}.{self.__class__.__qualname__}")
        self._playlist_unchanged_timeout = 0.5 * self.session.options.get("stream-timeout")
        self._playlist_changed_timestamp = time.time()

    def reload_playlist(self):
        super().reload_playlist()
        """
        For the live streaming of Eplus, there is no "#EXT-X-ENDLIST" tag in the playlists. It's OK because they are "Live
        Playlists" (rfc8216 § 6.2.2). However, when a live ends, the playlist still doesn't contain an "#EXT-X-ENDLIST" tag,
        and its content has not been changed since then. At the same time, the "worker" (self) keeps reloading the playlist
        but is not able to get any new stream. Since no new data is written to the buffer, after "stream-timeout" seconds,
        the "reader" will throw an exception and cause Streamlink to exit with a non-zero code.
        Thus, to gracefully shutdown Streamlink, we think:
          If the playlist remains unchanged for a while, the live has ended.
        """
        if self.playlist_changed:
            self._playlist_changed_timestamp = time.time()
        elif (time.time() - self._playlist_changed_timestamp) > self._playlist_unchanged_timeout:
            self._log.debug(
                f"The {self._playlist_unchanged_timeout}-second timeout reached, "
                "this is the last playlist. "
            )
            self.close()


class EplusHLSStreamReader(HLSStreamReader):
    __worker__ = EplusHLSStreamWorker

    stream: "EplusHLSStream"

    def open(self):
        super().open()
        if self.stream._session_updater:
            self.stream._session_updater.start()

    def close(self):
        super().close()
        if self.stream._session_updater:
            self.stream._session_updater.close()


class EplusHLSStream(HLSStream):
    __reader__ = EplusHLSStreamReader

    _session_updater: EplusSessionUpdater | None

    @classmethod
    def parse_variant_playlist(cls, session, m3u8_url, eplus_data: EplusData):
        the_map: Dict[str, EplusHLSStream] = super().parse_variant_playlist(session, m3u8_url)
        for _, stream in the_map.items():
            stream._session_updater = EplusSessionUpdater.make(session.http, eplus_data)
        return the_map


# Eplus inbound pages
# https://live.eplus.jp/ex/player?ib=<key>
# key is base64-encoded 64 byte unique key per ticket
@pluginmatcher(re.compile(
    r"https://live\.eplus\.jp/ex/player\?ib=.+"
))
# DRM test page and Eplus local pages
@pluginmatcher(re.compile(
    r"https://live\.eplus\.jp/(?:sample|\d+)"
))
@pluginargument(
    "id",
    metavar="ID",
    help="The email address or mobile phone number associated with your Eplus account",
)
@pluginargument(
    "password",
    metavar="PASSWORD",
    help="The password of your Eplus account",
)
@pluginargument(
    "allow-relogin",
    action="store_true",
    help="Allow to kick other sessions",
)
class Eplus(Plugin):

    _ORIGIN = "https://live.eplus.jp"
    _REFERER = "https://live.eplus.jp/"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.http.headers.update(
            {
                "Origin": self._ORIGIN,
                "Referer": self._REFERER,
                "User-Agent": useragents.SAFARI,
            }
        )
        self.title = None

    def _get_streams(self):
        eplus_data = EplusData(
            self.session.http,
            self.url,
            self.get_option("id"),
            self.get_option("password"),
            self.get_option("allow-relogin"),
        )
        self.id = eplus_data.app_id
        self.title = eplus_data.title
        m3u8_urls = eplus_data.m3u8_urls

        # Multiple m3u8 playlists? I have never seen it.
        # For recent events of "Revue Starlight", a "multi-angle video" does not mean that there are
        #   multiple playlists, but multiple cameras in one video. That's an edited video so viewers
        #   cannot switch views.
        for m3u8_url in m3u8_urls:
            yield from EplusHLSStream.parse_variant_playlist(
                self.session, m3u8_url, eplus_data,
            ).items()


__plugin__ = Eplus
