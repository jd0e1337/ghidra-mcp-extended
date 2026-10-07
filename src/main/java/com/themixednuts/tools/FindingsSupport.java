package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FindingsSnapshot;
import com.themixednuts.models.FindingsSnapshot.Comparison;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.JsonMapperHolder;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;

/** Owns loaded programs and publication of detached findings to the host filesystem. */
class FindingsSupport {
  private static final int MAX_JSON_BYTES = 8 * 1024 * 1024;
  private final ProgramLifecycleSupport lifecycle = new ProgramLifecycleSupport();
  private final FindingsReader reader;

  FindingsSupport() {
    this(new FindingsReader());
  }

  FindingsSupport(FindingsReader reader) {
    this.reader = reader;
  }

  FindingsSnapshot capture(
      Project project,
      String fileName,
      List<String> addresses,
      List<String> structures,
      int timeout,
      TaskMonitor monitor)
      throws Exception {
    return capture(
        lifecycle.resolveProgram(project, fileName), addresses, structures, timeout, monitor);
  }

  private FindingsSnapshot capture(
      DomainFile file,
      List<String> addresses,
      List<String> structures,
      int timeout,
      TaskMonitor monitor)
      throws Exception {
    monitor.checkCancelled();
    Object consumer = new Object();
    var object = file.getDomainObject(consumer, false, false, monitor);
    try {
      if (!(object instanceof Program program))
        throw new IllegalStateException("Selected file is not a Program");
      return reader.read(program, addresses, structures, timeout, monitor);
    } finally {
      if (object != null) object.release(consumer);
    }
  }

  Comparison compare(
      Project project,
      String leftFile,
      String leftAddress,
      String rightFile,
      String rightAddress,
      int timeout,
      TaskMonitor monitor)
      throws Exception {
    DomainFile left = lifecycle.resolveProgram(project, leftFile);
    DomainFile right = lifecycle.resolveProgram(project, rightFile);
    if (left.equals(right))
      throw invalid("right_file_name", rightFile, "must select a different program");
    var a = capture(left, List.of(leftAddress), List.of(), timeout, monitor);
    var b = capture(right, List.of(rightAddress), List.of(), timeout, monitor);
    return FindingsReader.compare(a, b);
  }

  Path destination(String path, boolean overwrite) throws Exception {
    Path target = Path.of(path);
    if (!target.isAbsolute())
      throw invalid("path", path, "must be an absolute host-local output path");
    target = target.normalize();
    if (target.getParent() == null || !Files.isDirectory(target.getParent())) {
      throw invalid("path", path, "parent directory must already exist");
    }
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)
        && (!overwrite || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS))) {
      throw invalid(
          "path", path, "already exists; overwrite=true permits replacing a regular file only");
    }
    return target;
  }

  Map<String, Object> write(
      FindingsSnapshot snapshot, Path target, boolean overwrite, TaskMonitor monitor)
      throws Exception {
    byte[] json =
        JsonMapperHolder.getMapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(snapshot);
    if (json.length > MAX_JSON_BYTES) throw invalid("selection", "JSON", "export exceeds 8 MiB");
    monitor.checkCancelled();
    Path temporary = Files.createTempFile(target.getParent(), ".ghidra-findings-", ".tmp");
    try {
      Files.write(temporary, json);
      monitor.checkCancelled();
      destination(target.toString(), overwrite);
      // No-clobber by default. Explicit replacement requires atomic rename on the destination FS.
      if (overwrite)
        Files.move(
            temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      else Files.move(temporary, target);
      return Map.of(
          "schema_version",
          1,
          "path",
          target.toString(),
          "bytes_written",
          json.length,
          "function_count",
          snapshot.functions().size(),
          "structure_count",
          snapshot.structures().size(),
          "decompilation_failures",
          snapshot.functions().stream()
              .filter(f -> !"completed".equals(f.decompilation().status()))
              .count());
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private GhidraMcpException invalid(String arg, String value, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(arg, value, reason));
  }
}
