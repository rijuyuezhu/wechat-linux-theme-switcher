# wechat-linux-theme-switcher

> [!IMPORTANT]
> This repository is now archived because wechat now supports automatically switching the theme following the system since 4.1.13.

Switch WeChat Linux 4.x appearance by appending `gAppearanceKey` to WeChat's encrypted MMKV `global_config`.

## Usage

```bash
uv run wechat-linux-theme-switcher dark
uv run wechat-linux-theme-switcher light
```

By default, the tool refuses to write while WeChat is running. Quit WeChat first, pass `--force` if you accept the race/overwrite risk, or pass `--force-restart` to stop WeChat, write the config, and restart it.

```bash
uv run wechat-linux-theme-switcher dark --force
```

`--force` and `--force-restart` are mutually exclusive.

```bash
uv run wechat-linux-theme-switcher dark --force-restart
```

Preview without writing:

```bash
uv run wechat-linux-theme-switcher dark --dry-run
```

Default config path:

```text
~/Documents/xwechat_files/all_users/config/global_config
```

Backups are written next to the config as `global_config.bak` and `global_config.crc.bak`.
