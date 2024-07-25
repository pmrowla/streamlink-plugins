# streamlink-plugins

Custom plugins for [Streamlink](https://github.com/streamlink/streamlink) 5.5.0 and newer versions with Python 3.8 and newer version.

To use these plugins, clone this repo somewhere and run (or configure) streamlink with `--plugin-dir`.
Alternatively, individual plugins can be symlinked or downloaded to `~/.config/streamlink/plugins`
(`%APPDATA%\streamlink\plugins` on Windows).

## NHL.tv

- Login required to view any live game or archived game (VOD).
  `--nhltv-email`, `--nhltv-password` and `--nhltv-purge-credentials` options can be used to specify login credentials/behavior.
- Valid subscription is required to view most games, but accounts without a subscription can watch specially designated free games
- `--nhltv-prefer-french` and `--nhltv-prefer-team=TEAM` options can be used to give priority to French language broadcasts or a specific team's home/away broadcasts when determining "best" quality stream.
  By default, priority is given in the following order:

    1. National (English)
    2. Home
    3. Away
    4. National (French)

## eplus (e+)

https://eplus.jp/ plugin.

- Supports `live.eplus.jp/<id>` (local) and `live.eplus.jp/ex/player?ib=`
  (inbound) stream or VOD URLs.
- Login required to view live event or VOD on local eplus. `--eplus-id`
  and `--eplus-password` options can be used to specify login credentials.
  Specifying `ci_session` cookie by `--http-cookie` option is another way to
  access restricted content.
- Streamlink will count as one (desktop browser) "device" against the e+ limit
  when viewing a stream or VOD. Set `--eplus-allow-relogin` to kick other
  "devices" during download.
- `--player-passthrough=hls` is incompatible with e+ since the video player
  will not have access to the authenticated HTTP session.
- DRM-protected content is NOT supported. If you have been notified that an
  event is only available for Microsoft Edge on Windows or Safari on macOS,
  it's DRM.

## SPWN

https://spwn.jp/ plugin.

- Supports direct `spwn.jp/events/` (ticketed) stream or VOD URLs.
- Login and valid event ticket required to view any live event or VOD.
  `--spwn-email` and `--spwn-password` options can be used to specify login
  credentials. Social account (Twitter/Facebook/Google) login requires
  specifying the OAuth refresh token (i.e., `refresh_token`) directly with
  `--spwn-token`.
- When the `--spwn-low-latency` option is set and a low-latency (LL) stream is
  available, it will be preferred over the default stream.
  (`--spwn-low-latency` has no effect for VOD URLs)
- Streamlink will count as one (desktop browser) device against the SPWN limit
  when viewing a stream or VOD.

## Z-aN

https://www.zan-live.com/ plugin.

- Supports direct `zan-live.com/live/play` (ticketed) stream or VOD URLs.
- Login and valid event ticket required to view any live event or VOD.
  `--zan-email` and `--zan-password` options can be used to specify login
  credentials.
- Streamlink will count as one (desktop browser) device against the Z-aN limit
  when viewing a stream or VOD.
