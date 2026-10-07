package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.exceptions.GhidraMcpException;
import ghidra.framework.plugintool.PluginTool;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class ProgramsToolTest {
  @Test
  void missingArgumentsAndUnknownActionFailWithoutNeedingAnOpenProgram() {
    ProgramsTool tool = new ProgramsTool();
    for (Map<String, Object> args :
        List.<Map<String, Object>>of(
            Map.of(),
            Map.of("action", "import_program"),
            Map.of("action", "open_program"),
            Map.of("action", "binary_identity"),
            Map.of("action", "wrong"))) {
      assertThrows(GhidraMcpException.class, () -> tool.execute(null, args, null).block());
    }
  }

  @Test
  void toolIsRegisteredAndExposesHostFilesystemAccess() {
    assertTrue(
        ServiceLoader.load(BaseMcpTool.class).stream()
            .anyMatch(provider -> provider.type().equals(ProgramsTool.class)));
    var specification = new ProgramsTool().specification(null).tool();
    assertEquals(Boolean.TRUE, specification.annotations().openWorldHint());
    assertNull(specification.annotations().destructiveHint());
    assertNull(specification.annotations().idempotentHint());
    Map<?, ?> properties = (Map<?, ?>) specification.inputSchema().get("properties");
    assertTrue(properties.containsKey("path"));
    assertTrue(properties.containsKey("file_name"));
  }

  @Test
  void batchRejectsLifecycleOperationsBeforeStartingATransaction() {
    PluginTool plugin = mock(PluginTool.class);
    Map<String, Object> args =
        Map.of(
            "file_name",
            "client.dll",
            "operations",
            List.of(
                Map.of(
                    "tool",
                    "programs",
                    "arguments",
                    Map.of("action", "import_program", "path", "file.dll"))));
    GhidraMcpException error =
        assertThrows(
            GhidraMcpException.class,
            () -> new BatchOperationsTool().execute(null, args, plugin).block());
    assertTrue(error.getMessage().contains("outside batch_operations"));
  }
}
