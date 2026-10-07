package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraStateUtils;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Ghidra import ownership and the handoff from worker-loaded programs to the UI. */
class ProgramLifecycleSupport {
  Map<String, Object> importProgram(
      Project project, String sourcePath, String name, String folder, TaskMonitor monitor)
      throws Exception {
    Path source = Path.of(sourcePath);
    if (!source.isAbsolute() || !Files.isRegularFile(source) || !Files.isReadable(source)) {
      throw invalid(
          "path",
          sourcePath,
          "must be an absolute path to a readable regular file on the Ghidra host");
    }
    String savedName = name == null ? source.getFileName().toString() : name;
    if (savedName.isBlank()
        || savedName.contains("/")
        || savedName.contains("\\")
        || savedName.equals(".")
        || savedName.equals("..")) {
      throw invalid("name", savedName, "must be a non-empty single project filename");
    }
    if (!folder.startsWith("/") || project.getProjectData().getFolder(folder) == null) {
      throw invalid("project_folder", folder, "must identify an existing absolute project folder");
    }
    monitor.checkCancelled();
    // Save only the primary result: saving a set of libraries can leave a partial import.
    // Closing LoadResults releases every loader-owned reference, including unsaved libraries.
    try (LoadResults<Program> loaded = load(project, source, savedName, folder, monitor)) {
      monitor.checkCancelled();
      DomainFile saved = loaded.getPrimary().save(monitor);
      return Map.of(
          "action",
          "import_program",
          "file_name",
          saved.getName(),
          "project_path",
          saved.getPathname(),
          "source_path",
          source.toString(),
          "analysis_started",
          false);
    }
  }

  LoadResults<Program> load(
      Project project, Path source, String name, String folder, TaskMonitor monitor)
      throws Exception {
    return ProgramLoader.builder()
        .source(source.toFile())
        .project(project)
        .projectFolderPath(folder)
        .name(name)
        .monitor(monitor)
        .load();
  }

  Map<String, Object> openProgram(
      Project project, String fileName, PluginTool tool, TaskMonitor monitor) throws Exception {
    ProgramManager manager = tool == null ? null : tool.getService(ProgramManager.class);
    if (manager == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of("ProgramManager is unavailable; enable this tool in a CodeBrowser."));
    }
    DomainFile file = resolveProgram(project, fileName);
    monitor.checkCancelled();
    Object consumer = new Object();
    // Load off the Swing thread, without silently upgrading the program database.
    DomainObject object = file.getDomainObject(consumer, false, false, monitor);
    try {
      if (!(object instanceof Program program)) {
        throw invalid("file_name", fileName, "must identify a Program");
      }
      monitor.checkCancelled();
      showProgram(manager, program);
      return Map.of(
          "action",
          "open_program",
          "file_name",
          file.getName(),
          "project_path",
          file.getPathname(),
          "active",
          true);
    } finally {
      if (object != null) {
        object.release(consumer);
      }
    }
  }

  DomainFile resolveProgram(Project project, String fileName) throws GhidraMcpException {
    DomainFile file;
    if (fileName.startsWith("/")) {
      file = project.getProjectData().getFile(fileName);
    } else {
      List<DomainFile> files = new ArrayList<>();
      GhidraStateUtils.collectFilesRecursive(project.getProjectData().getRootFolder(), files);
      List<DomainFile> matches = files.stream().filter(f -> f.getName().equals(fileName)).toList();
      if (matches.size() > 1) {
        throw invalid(
            "file_name",
            fileName,
            "is ambiguous; use an absolute project path: "
                + matches.stream().map(DomainFile::getPathname).toList());
      }
      file = matches.isEmpty() ? null : matches.getFirst();
    }
    if (file == null || !Program.class.isAssignableFrom(file.getDomainObjectClass())) {
      throw invalid("file_name", fileName, "does not identify a program in the active project");
    }
    return file;
  }

  void showProgram(ProgramManager manager, Program program) throws GhidraMcpException {
    AtomicReference<Exception> failure = new AtomicReference<>();
    Swing.runNow(
        () -> {
          try {
            manager.openProgram(program, ProgramManager.OPEN_CURRENT);
            // OPEN_CURRENT alone does not activate an already-open program.
            manager.setCurrentProgram(program);
            if (manager.getCurrentProgram() != program || !manager.isVisible(program)) {
              throw new IllegalStateException(
                  "ProgramManager did not make the program visible and active");
            }
          } catch (Exception e) {
            failure.set(e);
          }
        });
    if (failure.get() != null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("open program", failure.get().getMessage()), failure.get());
    }
  }

  private GhidraMcpException invalid(String argument, String value, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(argument, value, reason));
  }
}
