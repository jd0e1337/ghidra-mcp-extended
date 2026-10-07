<div align="center">
<a href="https://github.com/themixednuts/GhidraMCP/releases"><img src="https://img.shields.io/github/v/release/themixednuts/GhidraMCP?label=latest%20release&style=flat-square" alt="GitHub release (latest by date)"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/themixednuts/GhidraMCP/build.yml?style=flat-square" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ghidra-12.1.4-blue?style=flat-square" alt="Tested Ghidra Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/stargazers"><img src="https://img.shields.io/github/stars/themixednuts/GhidraMCP?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/themixednuts/GhidraMCP/network/members"><img src="https://img.shields.io/github/forks/themixednuts/GhidraMCP?style=flat-square" alt="GitHub forks"></a>
</div>

<div align="center">

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

If your browser/GitHub blocks custom URI handlers, use the web fallback:
[Cursor install fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

</div>
<h1 align="center">GhidraMCP</h1>

> Connect Ghidra to MCP-compatible clients

Forked from [the original GhidraMCP repository](https://github.com/themixednuts/GhidraMCP).
This fork adds program import and opening through MCP. Original authorship and the MIT license
are retained; upstream release badges above refer to the original project.

Related project: [WinDbg MCP Server](https://github.com/themixednuts/windbg-mcp-server)

---

## ✨ Features
- 15 MCP tools covering analysis, inspection, editing, project workflows, and Version Tracking
- MCP resources for common program views such as program info, listing, imports/exports, strings, RTTI, and decompilation
- Built-in MCP prompts and argument completions for common reverse engineering workflows
- Structured responses with explicit per-call limits and opaque cursors for large datasets
- Large outputs are bounded by tool arguments such as `page_size`, `max_lines`, or `max_results`; pass returned `next_cursor` values back as `cursor` to continue
- Debugger support for Trace RMI connect/accept/launch, target lifecycle, trace/thread/stack/object discovery, live memory/register/watch operations, static mappings, remote methods, and emulation
- Typed memory mapping applies a data type and returns bounded byte-to-field rows for program memory or the active debugger trace
- Project workflows can rebase program image bases explicitly or from a PE binary's stated ImageBase
- Focused CodeBrowser and Debugger operations automatically navigate the user's active Ghidra UI to the relevant function or address

### Tool Commands

- **Analysis & inspection:** `analyze`, `inspect`, `script_guidance`
- **Program changes:** `annotate`, `functions`, `symbols`, `data_types`, `memory`, `delete`
- **Debugging:** `debugger`
- **Project workflows:** `project`, `programs`, `batch_operations`
- **Version tracking:** `vt_sessions`, `vt_operations`

### Resource Templates

- **Project overview:** `ghidra://programs`
- **Program views:** `ghidra://program/{name}/info`, `ghidra://program/{name}/functions`, `ghidra://program/{name}/symbols`, `ghidra://program/{name}/datatypes`, `ghidra://program/{name}/memory`
- **Triage views:** `ghidra://program/{name}/imports`, `ghidra://program/{name}/exports`, `ghidra://program/{name}/strings`, `ghidra://program/{name}/rtti`
- **Code views:** `ghidra://program/{name}/listing/{address}`, `ghidra://program/{name}/function/{address}/decompile`

### Prompts

- `analyze_function`
- `analyze_vtable`
- `compare_binaries`
- `find_vulnerabilities`
- `map_data_structures`
- `rename_analysis`
- `triage_binary`

---

## 🚀 Installation

Requires Ghidra `12.1.4`.

For this fork's added functionality, build the extension from this checkout using the
**Building from Source** instructions below and install `target/GhidraMCP-0.9.0.zip`.
The original project's releases do not include this fork's changes.

1. Download the latest release `zip` file from the
   [Releases](https://github.com/themixednuts/GhidraMCP/releases) page.
2. In Ghidra, go to `File` -> `Install Extensions...`.
3. Click the `+` button (Add extension) in the top right corner.
4. Navigate to the downloaded `zip` file and select it.
5. Ensure the `GhidraMCP` extension is checked in the list and click `OK`.
6. Restart Ghidra.

---

## ▶️ Usage

1. Start Ghidra with the GhidraMCP extension enabled.
2. Confirm the server port in **Configuration**.
3. Point your MCP client to `http://127.0.0.1:8080/mcp` (or your custom port).

> [!WARNING]
> **Script Error Dialogs:** Some script-driven operations can open a Ghidra error
> dialog. Close the dialog before continuing, or requests may appear to hang.

> [!TIP]
> **Finding program names:** Use the `ghidra://programs` resource to see the
> exact program names available in the current project.

## ⚙️ Configuration

### Import and open programs (fork addition)

Call the `programs` MCP tool with these arguments, in order:

```json
{"action":"import_program","path":"E:\\binaries\\client.dll","project_folder":"/","name":"client.dll"}
```

```json
{"action":"open_program","file_name":"/client.dll"}
```

`path` is an absolute local path on the **Ghidra server machine**, not a client upload.
The active project must be writable and the destination folder must already exist.
Import chooses Ghidra's best matching loader and default architecture; unsupported formats
fail rather than guessing a raw binary layout. Only the primary program is saved; dependent
libraries are not imported. Existing programs are never overwritten: Ghidra adds a unique
suffix when names collide. Always use the returned `project_path` for the following open call.
Import does not open the program or start automatic analysis. Run `project` with
`{"action":"run_analysis","file_name":"client.dll"}` separately when desired.

Opening requires `ProgramManager` in the current CodeBrowser. Bare names must be unique;
use an absolute project path if multiple folders contain the same filename. The program
is made visible and active, including when it was already open. Database upgrades are
not performed automatically. Neither operation is allowed inside `batch_operations`,
because project-file creation and UI ownership are outside a program transaction.

Install the rebuilt extension, restart Ghidra, and reconnect the MCP client to discover
the new `programs` tool.

API references: [ProgramLoader](https://ghidra.re/ghidra_docs/api/ghidra/app/util/importer/ProgramLoader.html),
[Loaded.save](https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/Loaded.html),
and [ProgramManager](https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html).

### Server settings

The GhidraMCP server can be configured through Ghidra's application-level
settings:

1. In Ghidra, go to **Browser** → **Edit** → **Tool Options**.
2. In the left panel, expand **Miscellaneous** and select **GhidraMCP HTTP
   Server**.
3. Configure the following options:
   - **Server Port**: The port number for the MCP server (default: 8080)
   - **Auto-start Server**: Whether to automatically start the server when
     Ghidra launches
   - **Request Timeout (seconds)**: Maximum time allowed for an MCP request
     before timing out (default: 600)
4. Click **OK** to save your settings.

## 🛠️ Building from Source

If you are installing from a GitHub release zip, you can skip this section.
The steps below are only for building from source.

1. Clone the repository:
   ```bash
   git clone https://github.com/themixednuts/GhidraMCP.git
   ```
2. Ensure you have JDK 21 or later installed.
3. Build the project with `just`:
   ```bash
   just package
   ```

   To run the same checks used by the main build CI:
   ```bash
   just ci
   ```

   Or use the Gradle wrapper directly:
   ```bash
   bash ./gradlew package
   ```

   On Windows PowerShell, use:
   ```powershell
   .\gradlew.bat package
   ```

   Ghidra jars are fetched automatically from the official release zip on first run.

   Useful development entrypoints:

   - `just test` runs the unit suite
   - `just test-e2e` runs the end-to-end suite
   - `just update-verification-metadata` refreshes Gradle dependency verification checksums after manual dependency changes
   - The manual "Dependency Maintenance" GitHub workflow validates dependency and Ghidra update candidates without opening bot PRs

4. The installable `zip` file is written to `target/` (for example,
   `target/GhidraMCP-0.9.0.zip`). Install it using the steps above.

### Optional: Install Local Pre-commit Checks

To run formatting checks and full integration tests before every commit:

```bash
just install-hooks
```

The installed pre-commit hook runs:

- `just fmt-check`
- `just test`
- `just test-e2e`

---

## 🔌 Configuring an MCP Client

Use this server URL in your client:

- `http://127.0.0.1:8080/mcp` (or your custom port)

Most clients use a config like:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

### Client Setup Instructions

<details>
<summary><strong><img src="https://claude.ai/favicon.ico" alt="Claude" width="16" height="16" valign="middle" />&nbsp;Claude Desktop</strong></summary>

Config path:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Add the JSON config above, then restart Claude Desktop.

</details>

<details>
<summary><strong><img src="https://claude.ai/favicon.ico" alt="Claude" width="16" height="16" valign="middle" />&nbsp;Claude Code (CLI)</strong></summary>

```bash
claude mcp add ghidra "http://127.0.0.1:8080/mcp" --transport http
```

</details>

<details>
<summary><strong><img src="https://cursor.com/favicon.ico" alt="Cursor" width="16" height="16" valign="middle" />&nbsp;Cursor</strong></summary>

- [Install via deep link](cursor://anysphere.cursor-deeplink/mcp/install?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)
- [Install via web fallback](https://cursor.com/install-mcp?name=ghidra&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvbWNwIn0%3D)

Manual config path: `~/.cursor/mcp_settings.json`

</details>

<details>
<summary><strong><img src="https://opencode.ai/favicon.ico" alt="OpenCode" width="16" height="16" valign="middle" />&nbsp;OpenCode</strong></summary>

Use `~/.config/opencode/opencode.json` (or project-level `opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ghidra": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "enabled": true
    }
  }
}
```

</details>

<details>
<summary><strong><img src="https://openai.com/favicon.ico" alt="Codex" width="16" height="16" valign="middle" />&nbsp;Codex CLI</strong></summary>

```bash
codex mcp add ghidra --url http://127.0.0.1:8080/mcp
```

Or add this to `~/.codex/config.toml`:

```toml
[mcp_servers.ghidra]
url = "http://127.0.0.1:8080/mcp"
```

</details>

---

> [!IMPORTANT]
> The default port is `8080` (configurable in Ghidra: **Browser** → **Edit** →
> **Tool Options** → **Miscellaneous** → **GhidraMCP HTTP Server**). If you
> change the port, update your client configuration accordingly. Ghidra must be
> running with the extension enabled for the client to connect.

> [!NOTE]
> **Timeout Issues:** If you encounter timeout problems, refer to the
> [Ghidra timeout configuration guide](https://github.com/NationalSecurityAgency/ghidra/issues/1613#issuecomment-597165377).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open
issues.

---

## Acknowledgements

This project is heavily inspired by and based on the work of
[LaurieWired](https://github.com/LaurieWired). Instead of using a bridge, this
plugin directly embeds the server in the plugin.
