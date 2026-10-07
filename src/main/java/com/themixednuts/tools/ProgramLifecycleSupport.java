package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.BinaryIdentity;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraStateUtils;
import com.themixednuts.utils.ProgramMetadataReader;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Ghidra import ownership and the handoff from worker-loaded programs to the UI. */
class ProgramLifecycleSupport {
  Map<String, Object> closeProgram(
      Project project, String fileName, PluginTool tool, TaskMonitor monitor) throws Exception {
    DomainFile file = resolveProgram(project, fileName);
    ProgramManager manager = tool == null ? null : tool.getService(ProgramManager.class);
    if (manager == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of("ProgramManager is unavailable in this tool."));
    }
    AtomicReference<Exception> failure = new AtomicReference<>();
    AtomicReference<String> status = new AtomicReference<>();
    Swing.runNow(
        () -> {
          try {
            monitor.checkCancelled();
            Program program =
                Arrays.stream(manager.getAllOpenPrograms())
                    .filter(p -> file.equals(p.getDomainFile()))
                    .findFirst()
                    .orElse(null);
            if (program == null) {
              status.set("already_closed");
              return;
            }
            Object consumer = new Object();
            if (!program.addConsumer(consumer)) {
              throw new IllegalStateException("Unable to acquire program ownership for close");
            }
            try {
              if (!program.lock("MCP close unchanged program")) {
                throw new GhidraMcpException(
                    GhidraMcpError.failed(
                        "close program", "A modification is in progress; retry when idle."));
              }
              try {
                if (program.isChanged() || program.isTemporary()) {
                  throw new GhidraMcpException(
                      GhidraMcpError.failed(
                          "close program",
                          "Unsaved changes or a temporary program; save explicitly before"
                              + " closing."));
                }
                monitor.checkCancelled();
                // The modification lock and explicit unchanged check make this dialog-free flag
                // safe.
                // No discard option is exposed. Keep our consumer until the lock has been released.
                if (!manager.closeProgram(program, true)
                    || Arrays.asList(manager.getAllOpenPrograms()).contains(program)) {
                  throw new GhidraMcpException(
                      GhidraMcpError.failed(
                          "close program",
                          "ProgramManager did not close the program in this tool."));
                }
                status.set("closed");
              } finally {
                program.unlock();
              }
            } finally {
              program.release(consumer);
            }
          } catch (Exception e) {
            failure.set(e);
          }
        });
    if (failure.get() != null) throw failure.get();
    return Map.of(
        "action",
        "close_program",
        "file_name",
        file.getName(),
        "project_path",
        file.getPathname(),
        "status",
        status.get());
  }

  BinaryIdentity binaryIdentity(Project project, String fileName, TaskMonitor monitor)
      throws Exception {
    DomainFile file = resolveProgram(project, fileName);
    monitor.checkCancelled();
    Object consumer = new Object();
    DomainObject object = file.getDomainObject(consumer, false, false, monitor);
    try {
      if (!(object instanceof Program program)) {
        throw invalid("file_name", fileName, "must identify a Program");
      }
      monitor.checkCancelled();
      return ProgramMetadataReader.readIdentity(program);
    } finally {
      if (object != null) object.release(consumer);
    }
  }

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
      showProgram(project, tool, program, monitor);
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

  /** Called on Swing: prefer an existing owner, then another program-capable tool. */
  private ProgramManager findOrLaunchManager(Project project, PluginTool tool, Program program)
      throws GhidraMcpException {
    List<ProgramManager> managers = new ArrayList<>();
    ProgramManager current = tool == null ? null : tool.getService(ProgramManager.class);
    if (current != null) managers.add(current);
    ToolServices services = project.getToolServices();
    if (services != null) {
      for (PluginTool running : services.getRunningTools()) {
        ProgramManager manager = running.getService(ProgramManager.class);
        if (manager != null && !managers.contains(manager)) managers.add(manager);
      }
    }
    for (ProgramManager manager : managers) {
      for (Program open : manager.getAllOpenPrograms()) {
        if (program.getDomainFile().equals(open.getDomainFile())) return manager;
      }
    }
    if (!managers.isEmpty()) return managers.getFirst();
    if (services == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("open program", "Project ToolServices are unavailable."));
    }
    // Launch empty: database loading remains off Swing, without upgrade/analysis dialogs.
    // ToolServices may reuse an instance; never dispose the returned tool on a later failure.
    PluginTool browser = services.launchTool("CodeBrowser", List.of());
    ProgramManager manager = browser == null ? null : browser.getService(ProgramManager.class);
    if (manager == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "open program", "Unable to launch a CodeBrowser with ProgramManager."));
    }
    return manager;
  }

  void showProgram(Project project, PluginTool tool, Program program, TaskMonitor monitor)
      throws Exception {
    AtomicReference<Exception> failure = new AtomicReference<>();
    Swing.runNow(
        () -> {
          try {
            monitor.checkCancelled();
            ProgramManager manager = findOrLaunchManager(project, tool, program);
            monitor.checkCancelled();
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
      if (failure.get() instanceof ghidra.util.exception.CancelledException) throw failure.get();
      throw new GhidraMcpException(
          GhidraMcpError.failed("open program", failure.get().getMessage()), failure.get());
    }
  }

  private GhidraMcpException invalid(String argument, String value, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(argument, value, reason));
  }
}
