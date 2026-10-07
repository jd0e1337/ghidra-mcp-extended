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
        Manage programs in the active project. import_program requires an absolute host-local
        path; optional name and project_folder select the name and existing folder. Saves only
        the primary program, without opening or analyzing; conflicts get a unique suffix.
        open_program requires file_name (unique name or absolute project path) and activates it
        in CodeBrowser. binary_identity requires file_name and returns recorded import SHA-256,
        original path, architecture, compiler and current imagebase; it does not verify the source
        file. Missing/invalid metadata is explicit. Read ghidra://programs for paths and use
        project.run_analysis separately. Not supported inside batch_operations.
        """)
public class ProgramsTool extends BaseMcpTool {
  private final ProgramLifecycleSupport lifecycle;

  public ProgramsTool() {
    this(new ProgramLifecycleSupport());
  }

  ProgramsTool(ProgramLifecycleSupport lifecycle) {
    this.lifecycle = lifecycle;
  }

  @Override
  public JsonSchema schema() {
    var root = createDraft7SchemaNode();
    root.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues("import_program", "open_program", "binary_identity")
            .description("Program lifecycle operation."));
    root.property(
        ARG_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "Absolute local binary path on the machine running Ghidra; import_program only."));
    root.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description(
                "Optional imported program name (one path component); default: source filename."));
    root.property(
        "project_folder",
        SchemaBuilder.string(mapper)
            .description(
                "Existing absolute project folder path; default: /; import_program only."));
    root.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper)
            .description(
                "Unique program name or absolute project path; required for open_program and"
                    + " binary_identity."));
    root.requiredProperty(ARG_ACTION);
    root.allOf(
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
                            List.of("import_program", "open_program", "binary_identity"),
                            Map.of())));
          };
        });
  }
}
