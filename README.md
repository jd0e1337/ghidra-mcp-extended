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
This fork adds program and directory import, opening/closing, analysis status, binary identity, findings export and explicit function comparison through MCP. Original authorship and the MIT license
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
- **Project workflows:** `project`, `programs`, `findings`, `batch_operations`
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
**Building from Source** instructions below and install `target/GhidraMCP-0.9.1.zip`.
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

### Analysis status and binary identity (stage 1)

Read current analysis activity with the `project` tool:

```json
{"action":"analysis_status","file_name":"client.dll"}
```

`state` is `running` (executing or scheduled), `inactive` (an existing manager reports
no activity), or `unknown` (no usable manager). The query does not create an analysis
manager or start analysis. `analyzed_flag` is Ghidra's recorded flag: `true`, `false`,
or `null` when absent. Neither `inactive` nor this flag proves that the latest run
completed or all analyzers succeeded. Ghidra has no queryable last-run history here,
so `last_run_outcome` remains `unknown`, including after a cancellation. The response
includes `observed_at` in UTC; it is a transient observation, not a readiness guarantee.

Read import identity and current program configuration with the `programs` tool:

```json
{"action":"binary_identity","file_name":"/client.dll"}
```

The versioned response includes the recorded import `sha256`, original `executable_path`,
format, language, processor, endianness, address size **in bits**, compiler specification,
and **current** imagebase. `sha256_status` distinguishes `available`, `missing` and
`invalid`; invalid recorded text is preserved rather than silently corrected. Missing
metadata is `null` and listed in `missing_fields`. A valid hash is normalized to lowercase.
`hash_source` is `program_database_import_metadata`; `original_file_verified` is `false`.
No source file is read or rehashed: its contents may have changed since import, and patched
program memory has a different identity. The action also works for project programs that
are not open in CodeBrowser, without automatically upgrading the database.

The existing `ghidra://program/{name}/info` resource reuses the same metadata reader
and adds `binaryIdentity` while retaining its existing top-level field names.

API references: [Program metadata](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html)
and [Ghidra 12.1.4 analysis manager](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java).

### Directory import and closing programs (stage 2)

Call `programs` to import matching files from a local directory:

```json
{"action":"import_directory","path":"E:\\binaries","file_pattern":"*.dll","recursive":false,"max_files":100,"project_folder":"/"}
```

The default filename glob is `*`, recursion defaults to `false`, and glob case sensitivity
follows the host filesystem. Symbolic links are not followed. All matching primary programs
are imported into the existing destination folder; subdirectory structure is not recreated.
Discovery finishes before imports begin. `max_files` defaults to 100 (maximum 500), and
discovery examines at most 10,000 entries. Exceeding either limit fails before any import.
Filesystem discovery failures also abort before importing; select a smaller or accessible directory.

The response contains `files` with `source_path`, `status`, actual saved `project_path`,
`existing_name_path` and an error `message` where applicable. A name collision is reported
and handled by the existing single-file importer with a unique suffix; imports are not
deduplicated by content. One failed file does not prevent the remaining files from importing.
`imported_count` and `failed_count` summarize the report; a successful MCP response does not
mean every file imported. Opening and analysis remain separate operations.

Cancellation preserves completed imports. Remaining discovered files are `not_processed`.
If a file is interrupted during import, it is `cancelled_outcome_unknown`: inspect the project
before retrying, because saving may already have occurred. `cancelled` and
`enumeration_complete` distinguish a partial discovery from a cancelled import sequence.
The report does not list files that had not been discovered when discovery was cancelled.

Close a program in the current CodeBrowser using:

```json
{"action":"close_program","file_name":"/client.dll"}
```

This action does not reopen a closed program and returns `already_closed` when appropriate.
It refuses unsaved changes, temporary programs and active modifications. The unchanged check
and close run under a modification lock on the Swing thread; temporary ownership keeps the
program alive until the lock is released. No save/discard choice is exposed and no save dialog
is opened. `closed` is returned only after checking that ProgramManager no longer lists it.
Programs held by other tools remain owned by those tools.

API references: [ProgramManager.closeProgram](https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html)
and [DomainObject modification locks](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html).

### Findings export and explicit function comparison (stage 3)

The `findings` tool exports a selection as versioned JSON on the Ghidra host:

```json
{"action":"export_findings","file_name":"/client.dll","function_addresses":["+0x12340"],"structure_paths":["/types/PlayerState"],"path":"E:\\reports\\client-findings.json"}
```

Select at least one function or structure, with at most 25 of each. Function addresses must
identify exact entry points; address syntax is shared with `inspect`, including image-base-relative
offsets. Structure paths are absolute data type paths. The output directory must exist. Existing
output files are refused by default; `overwrite:true` explicitly enables atomic replacement of
a regular file. If the filesystem does not support atomic replacement, that operation fails.
The export is fully captured and serialized before publishing; cancellation before publishing
leaves existing output intact. A cancellation racing with publication can leave a complete export;
inspect the destination before retrying. Filesystem output is not transactionally reversible, so
`findings` is excluded from `batch_operations`.

The JSON includes `schema_version:1`, capture time, program modification number, unsaved-change
flag, and recorded binary identity. It describes the current Ghidra database, which may include
unsaved edits, rather than a fresh analysis or verification of the original binary. A modification
lock protects each capture; an actively modified program is refused. Programs are loaded with
temporary ownership, released after capture, and not opened in the CodeBrowser.

Function findings include signatures with source type, function and repeatable comments,
code-unit comments, instruction bytes, assembly and decompiler output. Each listing is bounded
to 2,000 code units with `listing_truncated` explicit. Structures include size, alignment, packing,
description and component offsets, lengths, names, type paths, comments and bitfield sizes/offsets;
referenced types are not recursively exported. Structures over 1,000 components are refused.
The snapshot text budget is 1,000,000 characters and the serialized export limit is 8 MiB;
exceeding either fails before publication. Each decompilation has a `completed`, `failed` or
`timeout` status; failure preserves other observed findings. `timeout` is 1–30 seconds per
function, defaulting to the smaller of 10 seconds and the configured request timeout.

Compare two deliberately selected functions from different project programs:

```json
{"action":"compare_function","left_file_name":"/old/client.dll","left_address":"+0x12340","right_file_name":"/new/client.dll","right_address":"+0x12670","timeout":10}
```

The result contains independently captured `left` and `right` snapshots and exact equality for
signature, instruction bytes, assembly and decompiler text, together with `observed_differences`
and `unknown`. Absolute entry addresses are reported separately; instruction equality uses
entry-relative positions. Embedded addresses, relocation bytes and decompiler identifiers are
not normalized. Truncated/missing listings and failed decompilations produce unknown equality,
never a claim that missing outputs match. The result makes no claim of semantic equivalence
or ABI compatibility. It does not create or apply Version Tracking matches; use `vt_sessions`
and `vt_operations` for matching workflows, then explicitly select entries here.

API references: [Function signatures and comments](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html),
[Structure components](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html),
and [DecompInterface lifecycle](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html).

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
   git clone https://github.com/jd0e1337/ghidra-mcp-extended.git
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
   `target/GhidraMCP-0.9.1.zip`). Install it using the steps above.

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
