# -*- coding: utf-8 -*-
"""spwn.jp streamlink plugin.

Requires valid SPWN account and event tickets.
"""

import logging
import re
from datetime import datetime, timedelta

import requests
from streamlink.plugin import Plugin, PluginArgument, PluginArguments, PluginError
from streamlink.plugin.api import useragents
from streamlink.plugin.api.utils import itertags
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)


class FBSession:
    """Google firebase auth session."""

    _IDENTITY_URL = "https://www.googleapis.com/identitytoolkit/v3/relyingparty"
    _TOKEN_URL = "https://securetoken.googleapis.com/v1"

    def __init__(self, session, api_key, auth_domain, project_id):
        self.session = session
        self.api_key = api_key
        self.auth_domain = auth_domain
        self.project_id = project_id
        self._id_token = None
        self.refresh_token = None
        self.refresh_expires = None

    def set_refresh_token(self, refresh_token):
        self.refresh_token = refresh_token
        self.expires = datetime.min

    def login(self, email, password):
        url = f"{self._IDENTITY_URL}/verifyPassword"
        headers = {
            "access-control-request-headers": "content-type,x-client-version",
            "access-control-request-method": "POST",
        }
        self.session.http.options(
            url,
            headers=headers,
            params={"key": self.api_key},
        )
        headers = {
            "x-client-version": "Chrome/JsCore/7.20.0/FirebaseCore-web",
        }
        result = self.session.http.post(
            url,
            headers=headers,
            params={"key": self.api_key},
            data={
                "email": email, "password": password, "returnSecureToken": True
            },
        )
        data = result.json()
        self._id_token = data["idToken"]
        self.expires = datetime.now() + timedelta(
            seconds=int(data["expiresIn"])
        )
        self.refresh_token = data["refreshToken"]
        log.info(f"Logged into SPWN as {data['email']}")

    @property
    def id_token(self):
        if self._id_token and self.expires < datetime.now():
            return self._id_token
        if not self.refresh_token:
            raise ValueError("Not logged in, no refresh token")
        url = f"{self._TOKEN_URL}/token"
        headers = {
            "access-control-request-headers": "x-client-version",
            "access-control-request-method": "POST",
        }
        self.session.http.options(
            url,
            headers=headers,
            params={"key": self.api_key},
        )
        headers = {
            "x-client-version": "Chrome/JsCore/7.20.0/FirebaseCore-web",
        }
        result = self.session.http.post(
            url,
            headers=headers,
            params={"key": self.api_key},
            data={
                "grant_type": "refresh_token",
                "refreshToken": self.refresh_token,
            },
        )
        data = result.json()
        self.expires = datetime.now() + timedelta(
            seconds=int(data["expires_in"])
        )
        self._id_token = data["id_token"]
        return self._id_token


class Spwn(Plugin):

    _URL_RE = re.compile(r"https://(virtual\.)?spwn\.jp/events/(?P<eid>[^/]+)")
    _BASE_URL = "https://spwn.jp"
    _BALUS_URL = "https://us-central1-spwn-balus.cloudfunctions.net"
    _PUBLIC_URL = "https://public.spwn.jp"

    arguments = PluginArguments(
        PluginArgument(
            "email",
            metavar="EMAIL",
            requires=["password"],
            help="The email associated with your SPWN account.",
        ),
        PluginArgument(
            "password",
            sensitive=True,
            metavar="PASSWORD",
            help="Account password to use with --spwn-email.",
        ),
        PluginArgument(
            "token",
            sensitive=True,
            metavar="TOKEN",
            help="Account token to use (instead of --spwn-email / --spwn-token).",
        ),
        PluginArgument(
            "video-id",
            metavar="VIDEO-ID",
            help="The video ID to stream (if there are multiple in the event to choose from).",
        ),
    )

    def __init__(self, url):
        super().__init__(url)
        self.session.http.headers.update(
            {
                "Origin": self._BASE_URL,
                "Referer": self._BASE_URL,
                "User-Agent": useragents.CHROME,
            }
        )
        self._fb = FBSession(
            self.session,
            self._fetch_fb_api_key(),
            "spwn.jp",
            "spwn-balus",
        )
        self._authed = False
        self.title = None

    def _fetch_fb_api_key(self):
        # get firebase API key
        body = self.session.http.get(self._BASE_URL).text

        for script in itertags(body, "script"):
            src = script.attributes.get("src", "")
            m = re.match(r"/static/js/main.*\.js", src)
            if m:
                break
        else:
            return None
        body = self.session.http.get(f"{self._BASE_URL}{src}").text
        m = re.search(
            r'REACT_APP_FB_API_KEY:\s*"(?P<key>[a-zA-Z0-9\-]+)"', body
        )
        if m:
            return m.group("key")
        return None

    def _login(self):
        if not self._authed:
            token = self.options.get("token")
            if token:
                self._fb.set_refresh_token(token)
            else:
                self._fb.login(
                    self.options.get("email"), self.options.get("password")
                )
            self._authed = True

    @classmethod
    def can_handle_url(cls, url):
        return cls._URL_RE.match(url) is not None

    def get_title(self):
        return self.title

    def _get_streams(self):
        try:
            self._login()
        except Exception as e:
            raise PluginError("SPWN login failed") from e
        m = self._URL_RE.match(self.url)
        eid = m.group("eid")
        event_info = self._get_event_data(eid)
        self.title = event_info.get("title", eid)
        log.info(f"Found SPWN event: {self.title}")
        stream_info = self._get_streaming_key(eid)
        if stream_info.get("isError"):
            raise PluginError("Error fetching stream info from SPWN API")
        cookies = stream_info.get("cookies")
        if not cookies:
            if not stream_info.get("hasTickets"):
                log.error("You do not have a ticket for this event")
                return
            msg = stream_info.get("msg", "")
            log.info(f"No available stream for this event: {msg}")
            return
        video_ids = stream_info.get("videoIds", [])
        log.info(f"Found video IDs: {video_ids}")
        video_id = self.options.get("video-id") or [video_id for video_id in video_ids if video_id in cookies][-1]
        info = cookies.get(video_id, {}).get("default", {})
        for k, v in info.get("cookie", {}).items():
            cookie = requests.cookies.create_cookie(k, v)
            self.session.http.cookies.set_cookie(cookie)
        url = info.get("url")
        if not url:
            raise PluginError(f"No stream URL for {video_id}")
        return HLSStream.parse_variant_playlist(self.session, url)

    def _get_streaming_key(self, eid):
        url = f"{self._BALUS_URL}/get_streaming_key/"
        headers = {
            "Authorization": f"Bearer {self._fb.id_token}",
        }
        result = self.session.http.post(
            url, headers=headers, json={"eid": eid}
        )
        return result.json()

    def _get_event_data(self, eid):
        url = f"{self._PUBLIC_URL}/event-pages/{eid}/data.json"
        result = self.session.http.get(url)
        return result.json().get("basic_data", {})


__plugin__ = Spwn
