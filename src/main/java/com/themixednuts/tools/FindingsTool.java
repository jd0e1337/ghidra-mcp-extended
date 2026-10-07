package com.themixednuts.tools;

import com.themixednuts.GhidraMcpServer;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Findings",
    description = "Export selected findings or compare two selected functions.",
    mcpName = "findings",
    openWorldHint = true,
    mcpDescription =
        """
        export_findings writes versioned JSON to an absolute host-local path. Requires file_name
        and function_addresses and/or structure_paths (at most 25 each). Exact function entry
        addresses only, absolute structure paths; no implicit whole-program export. Existing
        files require overwrite=true. Includes recorded binary identity, signatures, comments,
        bounded assembly and decompilation status. compare_function requires left_file_name,
        left_address, right_file_name, right_address in different programs. Returns both snapshots
        and exact observed equality; unknown results stay explicit. No ABI or semantic inference.
        timeout bounds each decompilation (1-30 seconds). Not supported in batch_operations.
        """)
public class FindingsTool extends BaseMcpTool {
  private final FindingsSupport support = new FindingsSupport();

  @Override
  public JsonSchema schema() {
    var root = createDraft7SchemaNode();
    root.property(
        ARG_ACTION, SchemaBuilder.string(mapper).enumValues("export_findings", "compare_function"));
    for (String field :
        List.of(
            ARG_FILE_NAME,
            ARG_PATH,
            "left_file_name",
            "left_address",
            "right_file_name",
            "right_address")) {
      root.property(
          field,
          SchemaBuilder.string(mapper)
              .description(
                  field.equals(ARG_PATH)
                      ? "Absolute output path on the Ghidra host."
                      : "Explicit program selector or exact function entry address."));
    }
    root.property(
        "function_addresses",
        SchemaBuilder.array(mapper)
            .items(SchemaBuilder.string(mapper))
            .maxItems(FindingsReader.MAX_SELECTION)
            .description("Exact function entry addresses; image-base-relative forms supported."));
    root.property(
        "structure_paths",
        SchemaBuilder.array(mapper)
            .items(SchemaBuilder.string(mapper))
            .maxItems(FindingsReader.MAX_SELECTION)
            .description("Absolute data type paths of structures to export."));
    root.property(
        "overwrite",
        SchemaBuilder.bool(mapper)
            .description(
                "Allow atomic replacement of an existing regular output file; default false."));
    root.property(
        "timeout",
        SchemaBuilder.integer(mapper)
            .minimum(1)
            .maximum(30)
            .description(
                "Seconds per decompilation; default min(10, configured request timeout)."));
    root.requiredProperty(ARG_ACTION);
    root.allOf(
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue("export_findings")),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_FILE_NAME)
                    .requiredProperty(ARG_PATH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue("compare_function")),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty("left_file_name")
                    .requiredProperty("left_address")
                    .requiredProperty("right_file_name")
                    .requiredProperty("right_address")));
    return root.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.defer(
        () -> {
          String action = getRequiredStringArgument(args, ARG_ACTION);
          int timeout =
              getBoundedIntArgumentOrDefault(
                  args, "timeout", Math.min(10, GhidraMcpServer.getRequestTimeoutSeconds()), 1, 30);
          return switch (action) {
            case "export_findings" -> {
              String file = getRequiredStringArgument(args, ARG_FILE_NAME);
              String path = getRequiredStringArgument(args, ARG_PATH);
              boolean overwrite = getOptionalBooleanArgument(args, "overwrite").orElse(false);
              var functions = selection(args, "function_addresses");
              var structures = selection(args, "structure_paths");
              if (functions.isEmpty() && structures.isEmpty())
                throw invalid("selection", "select at least one function or structure");
              yield withTaskMonitor(
                  "findings.export_findings",
                  monitor -> {
                    var target = support.destination(path, overwrite);
                    var snapshot =
                        support.capture(
                            getActiveProject(), file, functions, structures, timeout, monitor);
                    return support.write(snapshot, target, overwrite, monitor);
                  });
            }
            case "compare_function" -> {
              String left = getRequiredStringArgument(args, "left_file_name");
              String leftAddress = getRequiredStringArgument(args, "left_address");
              String right = getRequiredStringArgument(args, "right_file_name");
              String rightAddress = getRequiredStringArgument(args, "right_address");
              yield withTaskMonitor(
                  "findings.compare_function",
                  monitor ->
                      support.compare(
                          getActiveProject(),
                          left,
                          leftAddress,
                          right,
                          rightAddress,
                          timeout,
                          monitor));
            }
            default ->
                Mono.error(invalid(ARG_ACTION, "expected export_findings or compare_function"));
          };
        });
  }

  private List<String> selection(Map<String, Object> args, String key) {
    Object raw = args.get(key);
    if (raw == null) return List.of();
    if (!(raw instanceof List<?> list) || list.size() > FindingsReader.MAX_SELECTION)
      throw invalid(key, "expected an array of at most 25 strings");
    List<String> selected = new ArrayList<>();
    for (Object item : list) {
      if (!(item instanceof String text) || text.isBlank() || text.length() > 4096)
        throw invalid(key, "expected non-empty strings of at most 4096 characters");
      if (!selected.contains(text)) selected.add(text);
    }
    return List.copyOf(selected);
  }

  private GhidraMcpException invalid(String arg, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(arg, reason));
  }
}
