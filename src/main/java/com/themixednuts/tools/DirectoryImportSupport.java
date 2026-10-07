package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DirectoryImportResult;
import com.themixednuts.models.DirectoryImportResult.FileResult;
import com.themixednuts.models.DirectoryImportResult.Status;
import com.themixednuts.models.GhidraMcpError;
import ghidra.framework.model.Project;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** File discovery and sequential coordination; individual imports keep their existing owner. */
class DirectoryImportSupport {
  static final int MAX_FILES = 500;
  private static final int MAX_SCAN_ENTRIES = 10_000;
  private final ProgramLifecycleSupport lifecycle;

  DirectoryImportSupport(ProgramLifecycleSupport lifecycle) {
    this.lifecycle = lifecycle;
  }

  DirectoryImportResult importDirectory(
      Project project,
      String directory,
      String pattern,
      boolean recursive,
      int maxFiles,
      String folder,
      TaskMonitor monitor)
      throws Exception {
    Path root = Path.of(directory);
    if (!root.isAbsolute()
        || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
        || !Files.isReadable(root)) {
      throw invalid(
          "path", directory, "must be an absolute readable local directory (not a symlink)");
    }
    if (maxFiles < 1 || maxFiles > MAX_FILES) {
      throw invalid("max_files", Integer.toString(maxFiles), "must be between 1 and " + MAX_FILES);
    }
    if (pattern.isBlank() || pattern.contains("/") || pattern.contains("\\")) {
      throw invalid(
          "file_pattern", pattern, "must be a filename glob, without directory components");
    }
    var matcher = root.getFileSystem().getPathMatcher("glob:" + pattern);
    var target = project.getProjectData().getFolder(folder);
    if (!folder.startsWith("/") || target == null) {
      throw invalid("project_folder", folder, "must identify an existing absolute project folder");
    }
    List<Path> candidates = new ArrayList<>();
    try (var paths = Files.walk(root, recursive ? Integer.MAX_VALUE : 1)) {
      var iterator = paths.iterator();
      int scanned = 0;
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        if (++scanned > MAX_SCAN_ENTRIES) {
          throw invalid(
              "path",
              directory,
              "scan exceeds " + MAX_SCAN_ENTRIES + " entries; select a smaller directory");
        }
        Path path = iterator.next();
        if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
            && matcher.matches(path.getFileName())) {
          candidates.add(path);
          if (candidates.size() > maxFiles) {
            throw invalid(
                "max_files",
                Integer.toString(maxFiles),
                "matching files exceed the limit; no imports were started");
          }
        }
      }
    } catch (CancelledException e) {
      return result(
          root,
          true,
          false,
          candidates.stream()
              .map(
                  p ->
                      new FileResult(
                          p.toString(), Status.NOT_PROCESSED, null, null, "Discovery cancelled"))
              .toList());
    }
    candidates.sort(Comparator.comparing(p -> root.relativize(p).toString()));
    List<FileResult> results = new ArrayList<>();
    boolean cancelled = false;
    monitor.initialize(candidates.size());
    for (Path source : candidates) {
      if (cancelled || monitor.isCancelled()) {
        cancelled = true;
        results.add(
            new FileResult(
                source.toString(), Status.NOT_PROCESSED, null, null, "Import cancelled"));
        continue;
      }
      String existingPath = null;
      try {
        var existing = target.getFile(source.getFileName().toString());
        existingPath = existing == null ? null : existing.getPathname();
        monitor.setMessage("Importing " + source.getFileName());
        var imported = lifecycle.importProgram(project, source.toString(), null, folder, monitor);
        results.add(
            new FileResult(
                source.toString(),
                Status.IMPORTED,
                (String) imported.get("project_path"),
                existingPath,
                null));
      } catch (CancelledException e) {
        cancelled = true;
        results.add(
            new FileResult(
                source.toString(),
                Status.CANCELLED_OUTCOME_UNKNOWN,
                null,
                existingPath,
                "Cancelled during import; inspect the project before retrying this file"));
      } catch (Exception e) {
        results.add(
            new FileResult(
                source.toString(),
                Status.FAILED,
                null,
                existingPath,
                e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
      }
      monitor.incrementProgress(1);
    }
    return result(root, cancelled || monitor.isCancelled(), true, results);
  }

  private DirectoryImportResult result(
      Path root, boolean cancelled, boolean enumerated, List<FileResult> files) {
    return new DirectoryImportResult(
        1,
        root.toString(),
        cancelled,
        enumerated,
        files.stream().filter(f -> f.status() == Status.IMPORTED).count(),
        files.stream().filter(f -> f.status() == Status.FAILED).count(),
        files);
  }

  private GhidraMcpException invalid(String arg, String value, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(arg, value, reason));
  }
}
