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
    description = "Import local binaries into the active project and open project programs.",
    mcpName = "programs",
    openWorldHint = true,
    mcpDescription =
        """
        Import or open programs in the active Ghidra project. import_program requires path (an
        absolute file path on the Ghidra host); optional name and project_folder select the saved
        program name and existing destination folder. Imports save only the primary program,
        without opening or analyzing it. Existing files are never overwritten; naming conflicts
        receive a unique suffix. open_program requires file_name (a unique name or absolute project
        path) and makes the program active in the current CodeBrowser. Read ghidra://programs for
        saved paths. Use project.run_analysis separately. Not supported inside batch_operations.
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
            .enumValues("import_program", "open_program")
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
                "Unique program name or absolute project path; required for open_program."));
    root.requiredProperty(ARG_ACTION);
    root.allOf(
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
            default ->
                Mono.error(
                    new GhidraMcpException(
                        com.themixednuts.utils.GhidraMcpErrorUtils.invalidAction(
                            action, List.of("import_program", "open_program"), Map.of())));
          };
        });
  }
}
