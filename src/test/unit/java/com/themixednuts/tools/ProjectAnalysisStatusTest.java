package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.models.AnalysisStatus;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class ProjectAnalysisStatusTest {
  @Test
  void statusActionUsesProgramAndDoesNotStartAnalysisOrTransaction() {
    Program program = mock(Program.class);
    ProjectTool tool =
        new ProjectTool() {
          @Override
          protected Mono<Program> getProgram(Map<String, Object> args, PluginTool plugin) {
            return Mono.just(program);
          }
        };
    try (var managers = mockStatic(AutoAnalysisManager.class)) {
      assertInstanceOf(
          AnalysisStatus.class,
          tool.execute(null, Map.of("action", "analysis_status", "file_name", "client.dll"), null)
              .block());
      managers.verify(() -> AutoAnalysisManager.getAnalysisManager(program), never());
      verify(program, never()).startTransaction(anyString());
    }
    assertTrue(
        tool.schema()
            .getNode()
            .get("properties")
            .get("action")
            .get("enum")
            .toString()
            .contains("analysis_status"));
  }
}
