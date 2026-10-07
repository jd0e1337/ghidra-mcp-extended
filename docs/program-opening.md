# Opening programs from the project-level MCP

## Problem and implementation plan

The MCP plugin runs in Ghidra's project window. That tool has no ProgramManager,
so querying only the plugin tool made `programs.open_program` fail even with a
CodeBrowser running.

1. Resolve the requested project file and load it on the worker with an explicit
   temporary consumer, without automatically upgrading its database.
2. On Swing, inspect the caller and the project's running tools for ProgramManager.
   Prefer a manager already holding the requested DomainFile; otherwise reuse the
   first available manager, with the caller first.
3. If no manager exists, launch the `CodeBrowser` template with an empty file list
   through the project's ToolServices. This keeps program loading outside Swing.
4. Open the already loaded Program, explicitly activate it, and verify visibility
   and current-program identity before reporting success.
5. Preserve cancellation and release temporary ownership on every exit. Do not
   dispose a returned tool on failure: ToolServices may have reused a tool.

These steps are implemented in ProgramLifecycleSupport. No new Ghidra process,
MCP listener or automatic analysis is started. The existing project-level MCP
continues to serve program data. This change covers `open_program`; the existing
`close_program` caller-local manager requirement remains unchanged.

## Validation and limits

Unit scenarios cover existing owners, empty browsers, no-browser launch on Swing,
failed launch, missing manager, invalid file, cancellation before handoff, failed
activation and release of temporary ownership. A missing CodeBrowser template or
missing project ToolServices is an explicit error.

An empty tool can remain after cancellation following launch or a failed handoff.
The operation never closes a tool that might have been reused by Ghidra.
Live verification requires installing the rebuilt extension and restarting
Ghidra; the currently installed 0.9.1 listener does not contain this change.

## Official API references

- [ToolServices](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolServices.html):
  getRunningTools and launchTool (including empty file lists and possible reuse).
- [ProgramManager](https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html):
  openProgram, setCurrentProgram, getAllOpenPrograms and isVisible.

The build compiles against the repository's pinned Ghidra 12.1.4 libraries.
