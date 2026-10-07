package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DirectoryImportResult.Status;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
class DirectoryImportSupportTest {
  @TempDir Path temp;
  private Project project;
  private DomainFolder folder;
  private final List<String> imported = new ArrayList<>();
  private TaskMonitorAdapter monitor;
  private DirectoryImportSupport imports;

  @BeforeEach
  void setUp() {
    project = mock(Project.class);
    ProjectData data = mock(ProjectData.class);
    folder = mock(DomainFolder.class);
    when(project.getProjectData()).thenReturn(data);
    when(data.getFolder("/")).thenReturn(folder);
    monitor = new TaskMonitorAdapter(true);
    imports =
        new DirectoryImportSupport(
            new ProgramLifecycleSupport() {
              @Override
              Map<String, Object> importProgram(
                  Project project, String source, String name, String target, TaskMonitor task)
                  throws Exception {
                String file = Path.of(source).getFileName().toString();
                if (file.equals("bad.dll")) throw new IOException("unsupported file");
                if (file.equals("cancel.dll")) throw new CancelledException();
                imported.add(file);
                return Map.of("project_path", "/" + file + ".1");
              }
            });
  }

  @Test
  void mixedFilesReportFailuresAndActualCollisionPathsInSortedOrder() throws Exception {
    Files.write(temp.resolve("good.dll"), new byte[] {1});
    Files.write(temp.resolve("bad.dll"), new byte[] {1});
    Files.write(temp.resolve("ignore.txt"), new byte[] {1});
    DomainFile existing = mock(DomainFile.class);
    when(folder.getFile("good.dll")).thenReturn(existing);
    when(existing.getPathname()).thenReturn("/good.dll");
    var result =
        imports.importDirectory(project, temp.toString(), "*.dll", false, 10, "/", monitor);
    assertFalse(result.cancelled());
    assertEquals(1, result.importedCount());
    assertEquals(1, result.failedCount());
    assertEquals(Status.FAILED, result.files().getFirst().status());
    assertEquals("/good.dll.1", result.files().getLast().projectPath());
    assertEquals("/good.dll", result.files().getLast().existingNamePath());
  }

  @Test
  void recursionIsOptionalAndFileLimitFailsBeforeAnyImport() throws Exception {
    Files.write(temp.resolve("first.dll"), new byte[] {1});
    Files.createDirectories(temp.resolve("sub"));
    Files.write(temp.resolve("sub/second.dll"), new byte[] {1});
    assertEquals(
        1,
        imports
            .importDirectory(project, temp.toString(), "*.dll", false, 1, "/", monitor)
            .files()
            .size());
    imported.clear();
    assertThrows(
        GhidraMcpException.class,
        () -> imports.importDirectory(project, temp.toString(), "*.dll", true, 1, "/", monitor));
    assertTrue(imported.isEmpty());
    assertEquals(
        2,
        imports
            .importDirectory(project, temp.toString(), "*.dll", true, 2, "/", monitor)
            .files()
            .size());
  }

  @Test
  void cancellationKeepsCompletedImportsAndMarksRemainingFiles() throws Exception {
    for (String file : List.of("aaa.dll", "cancel.dll", "zzz.dll"))
      Files.write(temp.resolve(file), new byte[] {1});
    var result =
        imports.importDirectory(project, temp.toString(), "*.dll", false, 10, "/", monitor);
    assertTrue(result.cancelled());
    assertTrue(result.enumerationComplete());
    assertEquals(1, result.importedCount());
    assertEquals(Status.CANCELLED_OUTCOME_UNKNOWN, result.files().get(1).status());
    assertEquals(Status.NOT_PROCESSED, result.files().get(2).status());
    assertEquals(List.of("aaa.dll"), imported);
  }

  @Test
  void cancellationDuringDiscoveryAndInvalidInputDoNotStartImports() throws Exception {
    monitor.cancel();
    var result = imports.importDirectory(project, temp.toString(), "*", false, 10, "/", monitor);
    assertTrue(result.cancelled());
    assertFalse(result.enumerationComplete());
    assertTrue(imported.isEmpty());
    assertThrows(
        GhidraMcpException.class,
        () -> imports.importDirectory(project, "relative", "*", false, 10, "/", monitor));
    assertThrows(
        GhidraMcpException.class,
        () -> imports.importDirectory(project, temp.toString(), "../*", false, 10, "/", monitor));
    assertThrows(
        GhidraMcpException.class,
        () -> imports.importDirectory(project, temp.toString(), "*", false, 501, "/", monitor));
  }
}
