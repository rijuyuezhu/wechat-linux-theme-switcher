# wechat-linux-theme-switcher

Switch WeChat Linux 4.x appearance by appending `gAppearanceKey` to WeChat's encrypted MMKV `global_config`.

## Usage

```bash
uv run wechat-linux-theme-switcher dark
uv run wechat-linux-theme-switcher light
```

By default, the tool refuses to write while WeChat is running. Quit WeChat first, or pass `--force` if you accept the race/overwrite risk.

```bash
uv run wechat-linux-theme-switcher dark --force
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
