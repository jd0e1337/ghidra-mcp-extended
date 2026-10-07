package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.models.AnalysisStatus.State;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import org.junit.jupiter.api.Test;

class AnalysisStatusReaderTest {
  @Test
  void unavailableManagerIsUnknownAndIsNotCreatedByObservation() {
    Program program = mock(Program.class);
    try (var managers = mockStatic(AutoAnalysisManager.class)) {
      var result = AnalysisStatusReader.read(program);
      assertEquals(State.UNKNOWN, result.state());
      assertFalse(result.managerAvailable());
      assertNull(result.analyzedFlag());
      assertEquals("unknown", result.lastRunOutcome());
      managers.verify(() -> AutoAnalysisManager.getAnalysisManager(program), never());
    }
  }

  @Test
  void activityTransitionsDoNotInventCompletionOrCancellationHistory() {
    Program program = mock(Program.class);
    Options info = mock(Options.class);
    AutoAnalysisManager manager = mock(AutoAnalysisManager.class);
    when(program.getOptions(Program.PROGRAM_INFO)).thenReturn(info);
    when(info.contains(Program.ANALYZED_OPTION_NAME)).thenReturn(true);
    when(info.getBoolean(Program.ANALYZED_OPTION_NAME, false)).thenReturn(true);
    when(manager.getProgram()).thenReturn(program);
    when(manager.isAnalyzing()).thenReturn(true, false);
    try (var managers = mockStatic(AutoAnalysisManager.class)) {
      managers.when(() -> AutoAnalysisManager.hasAutoAnalysisManager(program)).thenReturn(true);
      managers.when(() -> AutoAnalysisManager.getAnalysisManager(program)).thenReturn(manager);
      var running = AnalysisStatusReader.read(program);
      var inactive = AnalysisStatusReader.read(program);
      assertEquals(State.RUNNING, running.state());
      assertEquals(State.INACTIVE, inactive.state());
      assertEquals(true, inactive.analyzedFlag());
      assertEquals("unknown", inactive.lastRunOutcome());
      assertNotNull(inactive.observedAt());
    }
  }

  @Test
  void missingFlagIsDifferentFromExplicitlyUnanalyzedProgram() {
    Program program = mock(Program.class);
    Options info = mock(Options.class);
    when(program.getOptions(Program.PROGRAM_INFO)).thenReturn(info);
    try (var managers = mockStatic(AutoAnalysisManager.class)) {
      assertNull(AnalysisStatusReader.read(program).analyzedFlag());
      when(info.contains(Program.ANALYZED_OPTION_NAME)).thenReturn(true);
      assertEquals(false, AnalysisStatusReader.read(program).analyzedFlag());
    }
  }

  @Test
  void disposedManagerDoesNotBecomeEvidenceOfInactivity() {
    Program program = mock(Program.class);
    AutoAnalysisManager manager = mock(AutoAnalysisManager.class);
    try (var managers = mockStatic(AutoAnalysisManager.class)) {
      managers.when(() -> AutoAnalysisManager.hasAutoAnalysisManager(program)).thenReturn(true);
      managers.when(() -> AutoAnalysisManager.getAnalysisManager(program)).thenReturn(manager);
      assertEquals(State.UNKNOWN, AnalysisStatusReader.read(program).state());
      verify(manager, never()).isAnalyzing();
    }
  }
}
