package com.themixednuts.utils;

import com.themixednuts.models.AnalysisStatus;
import com.themixednuts.models.AnalysisStatus.State;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import java.time.Instant;

/** Reads an existing analysis manager without creating or starting one. */
public final class AnalysisStatusReader {
  private AnalysisStatusReader() {}

  public static AnalysisStatus read(Program program) {
    boolean available;
    Boolean running = null;
    AutoAnalysisManager manager;
    // Keep the manager lookup together. getAnalysisManager alone creates a manager.
    synchronized (AutoAnalysisManager.class) {
      available = AutoAnalysisManager.hasAutoAnalysisManager(program);
      manager = available ? AutoAnalysisManager.getAnalysisManager(program) : null;
    }
    // Do not hold the global manager registry lock while acquiring an individual manager's lock.
    if (manager != null && manager.getProgram() == program && !program.isClosed()) {
      running = manager.isAnalyzing();
      if (manager.getProgram() != program || program.isClosed()) running = null;
    }
    var info = program.getOptions(Program.PROGRAM_INFO);
    Boolean analyzedFlag =
        info != null && info.contains(Program.ANALYZED_OPTION_NAME)
            ? info.getBoolean(Program.ANALYZED_OPTION_NAME, false)
            : null;
    var file = program.getDomainFile();
    State state = running == null ? State.UNKNOWN : running ? State.RUNNING : State.INACTIVE;
    return new AnalysisStatus(
        1,
        Instant.now().toString(),
        program.getName(),
        file == null ? null : file.getPathname(),
        state,
        available,
        analyzedFlag,
        "unknown",
        "Ghidra exposes current activity and an analyzed flag, but no queryable "
            + "last-run completion, cancellation or analyzer-success history.");
  }
}
