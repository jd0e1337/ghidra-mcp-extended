package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import reactor.core.publisher.Mono;

/** Project program lifecycle, independent of an already-open program. */
@GhidraMcpTool(
    name = "Programs",
    description = "Import and open project programs, or inspect their recorded binary identity.",
    mcpName = "programs",
    openWorldHint = true,
    mcpDescription =
        """
        Manage project programs. import_program takes an absolute host-local path, optional
        name and existing project_folder. import_directory takes path, file_pattern, recursive
        and max_files (default 100, max 500). Imports save primary programs without opening or
        analysis, never overwrite, and report per-file results and cancellation.
        open_program activates file_name (unique name or project path), reusing a program-capable
        tool or launching CodeBrowser if needed.
        close_program closes file_name only when unchanged; no save/discard dialog.
        binary_identity reads import hash and architecture; missing/invalid values are explicit,
        source files are not verified. Use ghidra://programs and project.run_analysis.
        Not supported inside batch_operations.
        """)
public class ProgramsTool extends BaseMcpTool {
  private final ProgramLifecycleSupport lifecycle;
  private final DirectoryImportSupport directoryImports;

  public ProgramsTool() {
    this(new ProgramLifecycleSupport());
  }

  ProgramsTool(ProgramLifecycleSupport lifecycle) {
    this.lifecycle = lifecycle;
    this.directoryImports = new DirectoryImportSupport(lifecycle);
  }

  @Override
  public JsonSchema schema() {
    var root = createDraft7SchemaNode();
    root.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                "import_program",
                "open_program",
                "binary_identity",
                "import_directory",
                "close_program")
            .description("Program lifecycle operation."));
    root.property(
        ARG_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "Absolute local file or directory path on the Ghidra host; required for imports."));
    root.property(
        "file_pattern",
        SchemaBuilder.string(mapper)
            .description(
                "Filename glob for import_directory; default *; host filesystem case rules"
                    + " apply."));
    root.property(
        "recursive",
        SchemaBuilder.bool(mapper)
            .description(
                "Include subdirectories in import_directory; default false; symlinks are not"
                    + " followed."));
    root.property(
        "max_files",
        SchemaBuilder.integer(mapper)
            .minimum(1)
            .maximum(DirectoryImportSupport.MAX_FILES)
            .description(
                "Maximum matching files for import_directory; default 100. Exceeding it fails"
                    + " before import."));
    root.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description(
                "Optional imported program name (one path component); default: source filename."));
    root.property(
        "project_folder",
        SchemaBuilder.string(mapper)
            .description("Existing absolute project folder path for imports; default: /."));
    root.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper)
            .description(
                "Unique program name or absolute project path; required for open_program and"
                    + " binary_identity and close_program."));
    root.requiredProperty(ARG_ACTION);
    root.allOf(
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue("import_directory")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_PATH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue("close_program")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue("binary_identity")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue("import_program")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_PATH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue("open_program")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)));
    return root.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.defer(
        () -> {
          String action = getRequiredStringArgument(args, ARG_ACTION).toLowerCase(Locale.ROOT);
          return switch (action) {
            case "import_directory" -> {
              String path = getRequiredStringArgument(args, ARG_PATH);
              String pattern = getOptionalStringArgument(args, "file_pattern").orElse("*");
              boolean recursive = getOptionalBooleanArgument(args, "recursive").orElse(false);
              int limit =
                  getBoundedIntArgumentOrDefault(
                      args, "max_files", 100, 1, DirectoryImportSupport.MAX_FILES);
              String folder = getOptionalStringArgument(args, "project_folder").orElse("/");
              yield withTaskMonitor(
                  "programs.import_directory",
                  monitor ->
                      directoryImports.importDirectory(
                          getActiveProject(), path, pattern, recursive, limit, folder, monitor));
            }
            case "close_program" -> {
              String fileName = getRequiredStringArgument(args, ARG_FILE_NAME);
              yield withTaskMonitor(
                  "programs.close_program",
                  monitor -> lifecycle.closeProgram(getActiveProject(), fileName, tool, monitor));
            }
            case "import_program" -> {
              String path = getRequiredStringArgument(args, ARG_PATH);
              String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
              String folder = getOptionalStringArgument(args, "project_folder").orElse("/");
              yield withTaskMonitor(
                  "programs.import_program",
                  monitor ->
                      lifecycle.importProgram(getActiveProject(), path, name, folder, monitor));
            }
            case "open_program" -> {
              String fileName = getRequiredStringArgument(args, ARG_FILE_NAME);
              yield withTaskMonitor(
                  "programs.open_program",
                  monitor -> lifecycle.openProgram(getActiveProject(), fileName, tool, monitor));
            }
            case "binary_identity" -> {
              String fileName = getRequiredStringArgument(args, ARG_FILE_NAME);
              yield withTaskMonitor(
                  "programs.binary_identity",
                  monitor -> lifecycle.binaryIdentity(getActiveProject(), fileName, monitor));
            }
            default ->
                Mono.error(
                    new GhidraMcpException(
                        com.themixednuts.utils.GhidraMcpErrorUtils.invalidAction(
                            action,
                            List.of(
                                "import_program",
                                "open_program",
                                "binary_identity",
                                "import_directory",
                                "close_program"),
                            Map.of())));
          };
        });
  }
}
