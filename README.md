# streamlink-plugins

Custom plugins for [Streamlink](https://github.com/streamlink/streamlink)

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

- Currently only supports direct `live.eplus.jp` (ticketed) stream or VOD URLs.
- Streamlink will count as one (desktop brower) "device" against the e+ limit
  when viewing a stream or VOD.
