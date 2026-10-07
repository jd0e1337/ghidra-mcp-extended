package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.List;
import java.util.Locale;

/** Bounded per-file import report. Cancellation never rolls back previously saved files. */
public record DirectoryImportResult(
    @JsonProperty("schema_version") int schemaVersion,
    @JsonProperty("directory") String directory,
    @JsonProperty("cancelled") boolean cancelled,
    @JsonProperty("enumeration_complete") boolean enumerationComplete,
    @JsonProperty("imported_count") long importedCount,
    @JsonProperty("failed_count") long failedCount,
    @JsonProperty("files") List<FileResult> files) {
  public DirectoryImportResult {
    files = List.copyOf(files);
  }

  public record FileResult(
      @JsonProperty("source_path") String sourcePath,
      @JsonProperty("status") Status status,
      @JsonProperty("project_path") String projectPath,
      @JsonProperty("existing_name_path") String existingNamePath,
      @JsonProperty("message") String message) {}

  public enum Status {
    IMPORTED,
    FAILED,
    NOT_PROCESSED,
    CANCELLED_OUTCOME_UNKNOWN;

    @JsonValue
    public String value() {
      return name().toLowerCase(Locale.ROOT);
    }
  }
}
