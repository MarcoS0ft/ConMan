# Connection Manager

ConMan is a cross-platform connection manager for local terminals, SSH,
Telnet, and RDP sessions. It keeps saved connections and credentials in their
platform-appropriate stores while keeping user preferences in an editable text
file.

## Configuration

ConMan's user preferences are stored in `conman.ini`. See the
[configuration reference](docs/configuration.md) for its location, syntax,
every supported setting, and the security implications of trust and automation
options.

The companion `conmanctl` command can print, validate, import, and export the
selected configuration:

```text
conmanctl config path
conmanctl config validate
conmanctl config export backup.ini
conmanctl config import backup.ini
```

Run `conman --help` or `conmanctl --help` for the complete command-line
interface.
