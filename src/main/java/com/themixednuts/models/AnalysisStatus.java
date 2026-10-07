package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

/** A point-in-time observation, not evidence that all analyzers succeeded. */
public record AnalysisStatus(
    @JsonProperty("schema_version") int schemaVersion,
    @JsonProperty("observed_at") String observedAt,
    @JsonProperty("file_name") String fileName,
    @JsonProperty("project_path") String projectPath,
    @JsonProperty("state") State state,
    @JsonProperty("manager_available") boolean managerAvailable,
    @JsonProperty("analyzed_flag") Boolean analyzedFlag,
    @JsonProperty("last_run_outcome") String lastRunOutcome,
    @JsonProperty("outcome_reason") String outcomeReason) {
  public enum State {
    RUNNING,
    INACTIVE,
    UNKNOWN;

    @JsonValue
    public String value() {
      return name().toLowerCase(Locale.ROOT);
    }
  }
}
