# -*- coding: utf-8 -*-
"""zan-live.com streamlink plugin.

Requires valid Z-aN account and event tickets.
"""

import logging
import re

from streamlink.plugin import (
    Plugin,
    PluginError,
    pluginargument,
    pluginmatcher,
)
from streamlink.plugin.api import useragents, validate
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)


@pluginmatcher(
    re.compile(
        r"https://(www\.)?zan-live\.com/([^/]+/)?live/play/(?P<ticket_id>[^/]+)/(?P<live_id>[^/]+)"
    )
)
@pluginargument(
    "email",
    metavar="EMAIL",
    requires=["password"],
    help="The email associated with your Z-aN account.",
    required=True,
)
@pluginargument(
    "password",
    sensitive=True,
    metavar="PASSWORD",
    help="Account password to use with --zan-email.",
)
class Zan(Plugin):

    _BASE_URL = "https://www.zan-live.com"
    _LOGIN_URL = f"{_BASE_URL}/auth/login"
    _PLAY_URL = f"{_BASE_URL}/live/play/{{ticket_id}}/{{live_id}}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.http.headers.update(
            {
                "Origin": self._BASE_URL,
                "Referer": self._BASE_URL,
                "User-Agent": useragents.CHROME,
            }
        )
        self._authed = False

    def _login(self):
        if self._authed:
            return
        csrf = ""
        for input_tag in self.session.http.get(
            self._LOGIN_URL,
            schema=validate.Schema(
                validate.parse_html(),
                validate.xml_findall(".//input[@name='_csrf']")
            )
        ):
            csrf = input_tag.get("value", "")
        email = self.options.get("email")
        password = self.options.get("password")
        data = {
            "mailAddress": email,
            "password": password,
            "isPersistentLogin": "1",
            "__submit__": "Log In",
            "_csrf": csrf,
        }
        self.session.http.post(self._LOGIN_URL, data=data)
        if not self.session.http.cookies.get("Z-aN_sid"):
            raise PluginError("Z-aN login failed")
        log.info(f"Logged into Z-aN as {email}")
        self._authed = True

    def get_title(self):
        return self.title

    def _get_streams(self):
        try:
            self._login()
        except Exception as e:
            raise PluginError("Z-an login failed") from e
        ticket_id = self.match.group("ticket_id")
        live_id = self.match.group("live_id")
        url = self._PLAY_URL.format(ticket_id=ticket_id, live_id=live_id)
        live_url = ""
        for meta_tag in self.session.http.get(
            url,
            schema=validate.Schema(
                validate.parse_html(),
                validate.xml_findall(".//meta[@name='live-url']"),
            ),
        ):
            live_url = meta_tag.get("content", "")
        playlist = {}
        if live_url:
            log.debug(f"Got live-url {live_url}")
            playlist.update(
                HLSStream.parse_variant_playlist(
                    self.session,
                    live_url,
                )
            )
        return playlist


__plugin__ = Zan
