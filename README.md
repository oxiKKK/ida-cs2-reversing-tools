IDA Pro CS2 Reversing Tools
---

A collection of IDA Pro plugins designed to automate and streamline the reverse engineering of Counter-Strike 2 and Source 2 engine binaries.

Since the CS2 (or other Source2 games) are updated on regular basis, it's not making life easier for a reverse-engineer that is actively reversing the game. In order to make the reversing of new CS2 binaries easier, this plugin introduces several tools that may help along the way.

The plugin includes tools such as **automatic interface renaming**, which automatically detects global interface variables used in the codebase and renames them accordingly. For instance, `g_pVApplication001` or `g_pVEngineCvar007`. Another tool is the **convar renamer**, which does a similar thing where it automatically detects convars/concommands across the IDB and renames them.

Happy Reversing!

> [!NOTE]
> This repository uses the [ida_domain](https://github.com/HexRaysSA/ida-domain) IDA Pro SDK.

## Features

- **Interface Table Renamer**: Automatically locates and renames Source 2 interface pointers (e.g., `ICvar`, `IEngineClient`) based on their interface identifiers
- **ConVar/ConCommand Renamer**: Renames global ConVar and ConCommand variables based on their registration string names

## Requirements

- IDA Pro 9.0 or later (with [ida_domain](https://github.com/HexRaysSA/ida-domain) API support)
- Python 3.x
- PyQt5

## Installation

1. Clone or download this repository:
   ```
   git clone https://github.com/oxiKKK/ida-cs2-reversing-tools.git
   ```

2. Copy the plugin files to your IDA Pro `plugins/` directory:
   1. copy the `cs2_reversing_tools.py` file.
   2. copy the `cs2_tools/` directory.

## Usage

After installation, the tools are accessible from the IDA Pro menu under **Edit > Plugins > CS2 Reversing Tools**.

## License

MIT License - see [LICENSE](LICENSE) for details.