package com.themixednuts.models;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/** Detached observations of one program; no Ghidra objects escape the reader. */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record FindingsSnapshot(
    int schemaVersion,
    String capturedAt,
    long modificationNumber,
    boolean unsavedChanges,
    String provenance,
    BinaryIdentity binaryIdentity,
    List<FunctionFinding> functions,
    List<StructureFinding> structures) {
  public FindingsSnapshot {
    functions = List.copyOf(functions);
    structures = List.copyOf(structures);
  }

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record FunctionFinding(
      String name,
      String entryPoint,
      String signature,
      String signatureSource,
      String comment,
      String repeatableComment,
      List<InstructionFinding> instructions,
      List<CommentFinding> comments,
      boolean listingTruncated,
      Decompilation decompilation) {
    public FunctionFinding {
      instructions = List.copyOf(instructions);
      comments = List.copyOf(comments);
    }
  }

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record InstructionFinding(String address, String entryOffset, String bytes, String text) {}

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record CommentFinding(String address, String type, String text) {}

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record Decompilation(String status, String code, String message) {}

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record StructureFinding(
      String path,
      int length,
      int alignment,
      boolean packed,
      String description,
      List<FieldFinding> fields) {
    public StructureFinding {
      fields = List.copyOf(fields);
    }
  }

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record FieldFinding(
      int ordinal,
      int offset,
      int length,
      String name,
      String typePath,
      String comment,
      Integer bitSize,
      Integer bitOffset) {}

  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public record Comparison(
      int schemaVersion,
      FindingsSnapshot left,
      FindingsSnapshot right,
      Boolean signatureEqual,
      Boolean instructionBytesEqual,
      Boolean assemblyEqual,
      Boolean decompiledCodeEqual,
      List<String> observedDifferences,
      List<String> unknown,
      String interpretation) {
    public Comparison {
      observedDifferences = List.copyOf(observedDifferences);
      unknown = List.copyOf(unknown);
    }
  }
}
