package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.themixednuts.exceptions.GhidraMcpException;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProgramLifecycleSupportTest {
  @TempDir Path temp;
  private Project project;
  private ProjectData data;
  private DomainFolder root;
  private TaskMonitor monitor;
  private ProgramLifecycleSupport support;

  @BeforeEach
  void setUp() {
    project = mock(Project.class);
    data = mock(ProjectData.class);
    root = mock(DomainFolder.class);
    monitor = mock(TaskMonitor.class);
    when(project.getProjectData()).thenReturn(data);
    when(data.getRootFolder()).thenReturn(root);
    when(data.getFolder("/")).thenReturn(root);
    support = new ProgramLifecycleSupport();
  }

  @Test
  void missingOrRelativeSourcesAndInvalidDestinationFailBeforeLoading() throws Exception {
    assertThrows(
        GhidraMcpException.class,
        () -> support.importProgram(project, "relative.dll", null, "/", monitor));
    assertThrows(
        GhidraMcpException.class,
        () ->
            support.importProgram(
                project, temp.resolve("absent.dll").toString(), null, "/", monitor));
    Path source = Files.write(temp.resolve("input.dll"), new byte[] {1});
    assertThrows(
        GhidraMcpException.class,
        () -> support.importProgram(project, source.toString(), "../escape.dll", "/", monitor));
    assertThrows(
        GhidraMcpException.class,
        () -> support.importProgram(project, source.toString(), null, "/missing", monitor));
  }

  @Test
  @SuppressWarnings("unchecked")
  void importReturnsActualCollisionResolvedPathAndClosesAllLoaderResults() throws Exception {
    LoadResults<Program> loaded = mock(LoadResults.class);
    Loaded<Program> primary = mock(Loaded.class);
    DomainFile saved = programFile("/input.dll.1");
    when(loaded.getPrimary()).thenReturn(primary);
    when(primary.save(monitor)).thenReturn(saved);
    ProgramLifecycleSupport importer = importerReturning(loaded);
    Path source = Files.write(temp.resolve("input.dll"), new byte[] {1});

    Map<String, Object> result =
        importer.importProgram(project, source.toString(), null, "/", monitor);

    assertEquals("/input.dll.1", result.get("project_path"));
    assertEquals(false, result.get("analysis_started"));
    verify(loaded).close();
    verify(loaded, never()).save(any());
  }

  @Test
  @SuppressWarnings("unchecked")
  void failedSaveReleasesLoadedProgramsAndDoesNotReportSuccess() throws Exception {
    LoadResults<Program> loaded = mock(LoadResults.class);
    Loaded<Program> primary = mock(Loaded.class);
    when(loaded.getPrimary()).thenReturn(primary);
    when(primary.save(monitor)).thenThrow(new IOException("project is read-only"));
    Path source = Files.write(temp.resolve("input.dll"), new byte[] {1});

    assertThrows(
        IOException.class,
        () ->
            importerReturning(loaded)
                .importProgram(project, source.toString(), null, "/", monitor));
    verify(loaded).close();
  }

  @Test
  void duplicateNamesRequireProjectPath() throws Exception {
    DomainFile first = programFile("/one/client.dll");
    DomainFile second = programFile("/two/client.dll");
    when(root.getFiles()).thenReturn(new DomainFile[] {first, second});
    when(root.getFolders()).thenReturn(new DomainFolder[0]);
    when(data.getFile("/two/client.dll")).thenReturn(second);

    assertThrows(GhidraMcpException.class, () -> support.resolveProgram(project, "client.dll"));
    assertSame(second, support.resolveProgram(project, "/two/client.dll"));
  }

  @Test
  void missingAndNonProgramFilesAreRejected() {
    DomainFile file = mock(DomainFile.class);
    doReturn(ghidra.framework.model.DomainObject.class).when(file).getDomainObjectClass();
    when(data.getFile("/types")).thenReturn(file);
    assertThrows(GhidraMcpException.class, () -> support.resolveProgram(project, "/missing"));
    assertThrows(GhidraMcpException.class, () -> support.resolveProgram(project, "/types"));
  }

  @Test
  void openingAnAlreadyOpenProgramActivatesItAndReleasesTemporaryOwnership() throws Exception {
    Program program = mock(Program.class);
    ProgramManager manager = mock(ProgramManager.class);
    PluginTool tool = mock(PluginTool.class);
    DomainFile file = programFile("/client.dll");
    when(data.getFile("/client.dll")).thenReturn(file);
    when(tool.getService(ProgramManager.class)).thenReturn(manager);
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor))).thenReturn(program);
    when(manager.getCurrentProgram()).thenReturn(program);
    when(manager.isVisible(program)).thenReturn(true);
    when(manager.getAllOpenPrograms()).thenReturn(new Program[0]);

    Map<String, Object> result = support.openProgram(project, "/client.dll", tool, monitor);

    assertEquals(true, result.get("active"));
    verify(manager).openProgram(program, ProgramManager.OPEN_CURRENT);
    verify(manager).setCurrentProgram(program);
    verify(program).release(any());
  }

  @Test
  void failedUiHandoffReleasesOwnershipAndDoesNotReportSuccess() throws Exception {
    Program program = mock(Program.class);
    ProgramManager manager = mock(ProgramManager.class);
    PluginTool tool = mock(PluginTool.class);
    DomainFile file = programFile("/client.dll");
    when(data.getFile("/client.dll")).thenReturn(file);
    when(tool.getService(ProgramManager.class)).thenReturn(manager);
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor))).thenReturn(program);
    when(manager.getAllOpenPrograms()).thenReturn(new Program[0]);

    assertThrows(
        GhidraMcpException.class, () -> support.openProgram(project, "/client.dll", tool, monitor));
    verify(program).release(any());
  }

  @Test
  void projectWindowReusesTheBrowserThatAlreadyOwnsTheFile() throws Exception {
    ToolServices services = mock(ToolServices.class);
    PluginTool projectWindow = mock(PluginTool.class);
    PluginTool emptyBrowser = mock(PluginTool.class);
    PluginTool owner = mock(PluginTool.class);
    ProgramManager emptyManager = mock(ProgramManager.class);
    ProgramManager ownerManager = mock(ProgramManager.class);
    DomainFile file = programFile("/server.dll");
    Program program = prepareOpen(file, ownerManager);
    when(project.getToolServices()).thenReturn(services);
    when(services.getRunningTools())
        .thenReturn(new PluginTool[] {projectWindow, emptyBrowser, owner});
    when(emptyBrowser.getService(ProgramManager.class)).thenReturn(emptyManager);
    when(emptyManager.getAllOpenPrograms()).thenReturn(new Program[0]);
    when(owner.getService(ProgramManager.class)).thenReturn(ownerManager);
    when(ownerManager.getAllOpenPrograms()).thenReturn(new Program[] {program});

    assertEquals(
        true, support.openProgram(project, "/server.dll", projectWindow, monitor).get("active"));

    verify(ownerManager).setCurrentProgram(program);
    verify(emptyManager, never()).openProgram(any(Program.class), anyInt());
    verify(services, never()).launchTool(anyString(), any());
    verify(program).release(any());
  }

  @Test
  void reusesAnEmptyBrowserWithoutLaunchingAnother() throws Exception {
    ToolServices services = mock(ToolServices.class);
    PluginTool browser = mock(PluginTool.class);
    ProgramManager manager = mock(ProgramManager.class);
    Program program = prepareOpen(programFile("/server.dll"), manager);
    when(project.getToolServices()).thenReturn(services);
    when(services.getRunningTools()).thenReturn(new PluginTool[] {browser});
    when(browser.getService(ProgramManager.class)).thenReturn(manager);
    when(manager.getAllOpenPrograms()).thenReturn(new Program[0]);

    support.openProgram(project, "/server.dll", null, monitor);

    verify(manager).openProgram(program, ProgramManager.OPEN_CURRENT);
    verify(services, never()).launchTool(anyString(), any());
  }

  @Test
  void launchesCodeBrowserOnSwingOnlyWhenNoProgramManagerExists() throws Exception {
    ToolServices services = mock(ToolServices.class);
    PluginTool browser = mock(PluginTool.class);
    ProgramManager manager = mock(ProgramManager.class);
    Program program = prepareOpen(programFile("/server.dll"), manager);
    when(project.getToolServices()).thenReturn(services);
    when(services.getRunningTools()).thenReturn(new PluginTool[0]);
    when(services.launchTool(eq("CodeBrowser"), eq(List.of())))
        .thenAnswer(
            invocation -> {
              assertTrue(SwingUtilities.isEventDispatchThread());
              return browser;
            });
    when(browser.getService(ProgramManager.class)).thenReturn(manager);
    doAnswer(
            invocation -> {
              assertTrue(SwingUtilities.isEventDispatchThread());
              return null;
            })
        .when(manager)
        .setCurrentProgram(program);

    // Ghidra executes Swing.runNow inline in headless tests. Dispatch to the real EDT
    // here to verify the desktop thread contract independently of that mode.
    try (var swing = mockStatic(ghidra.util.Swing.class)) {
      swing
          .when(() -> ghidra.util.Swing.runNow(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                SwingUtilities.invokeAndWait(invocation.getArgument(0, Runnable.class));
                return null;
              });
      assertEquals(true, support.openProgram(project, "/server.dll", null, monitor).get("active"));
    }

    verify(services).launchTool("CodeBrowser", List.of());
    verify(program).release(any());
  }

  @Test
  void failedLaunchOrMissingServiceReleasesLoadedProgram() throws Exception {
    ToolServices services = mock(ToolServices.class);
    Program program = prepareOpen(programFile("/server.dll"), mock(ProgramManager.class));
    when(project.getToolServices()).thenReturn(services);
    when(services.getRunningTools()).thenReturn(new PluginTool[0]);
    assertThrows(
        GhidraMcpException.class, () -> support.openProgram(project, "/server.dll", null, monitor));
    when(services.launchTool(eq("CodeBrowser"), any())).thenReturn(mock(PluginTool.class));
    assertThrows(
        GhidraMcpException.class, () -> support.openProgram(project, "/server.dll", null, monitor));
    verify(program, times(2)).release(any());
  }

  @Test
  void invalidFileAndCancellationDoNotLaunchBrowser() throws Exception {
    ToolServices services = mock(ToolServices.class);
    when(project.getToolServices()).thenReturn(services);
    assertThrows(
        GhidraMcpException.class, () -> support.openProgram(project, "/missing", null, monitor));
    Program program = prepareOpen(programFile("/server.dll"), mock(ProgramManager.class));
    DomainFile file = data.getFile("/server.dll");
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor)))
        .thenAnswer(
            invocation -> {
              doThrow(new CancelledException()).when(monitor).checkCancelled();
              return program;
            });
    assertThrows(
        CancelledException.class, () -> support.openProgram(project, "/server.dll", null, monitor));
    verifyNoInteractions(services);
    verify(program).release(any());
  }

  @Test
  void cancellationAfterLaunchDoesNotOpenProgramOrCloseTheReturnedTool() throws Exception {
    ToolServices services = mock(ToolServices.class);
    PluginTool browser = mock(PluginTool.class);
    ProgramManager manager = mock(ProgramManager.class);
    Program program = prepareOpen(programFile("/server.dll"), manager);
    when(project.getToolServices()).thenReturn(services);
    when(services.getRunningTools()).thenReturn(new PluginTool[0]);
    when(browser.getService(ProgramManager.class)).thenReturn(manager);
    when(services.launchTool(eq("CodeBrowser"), any()))
        .thenAnswer(
            invocation -> {
              doThrow(new CancelledException()).when(monitor).checkCancelled();
              return browser;
            });

    assertThrows(
        CancelledException.class, () -> support.openProgram(project, "/server.dll", null, monitor));

    verify(manager, never()).openProgram(any(Program.class), anyInt());
    verify(services, never()).closeTool(any());
    verify(program).release(any());
  }

  @Test
  void missingProjectToolServicesReleasesOwnershipAndReportsTheCause() throws Exception {
    Program program = prepareOpen(programFile("/server.dll"), mock(ProgramManager.class));
    GhidraMcpException failure =
        assertThrows(
            GhidraMcpException.class,
            () -> support.openProgram(project, "/server.dll", null, monitor));
    assertTrue(failure.getMessage().contains("ToolServices are unavailable"));
    verify(program).release(any());
  }

  private Program prepareOpen(DomainFile file, ProgramManager manager) throws Exception {
    Program program = mock(Program.class);
    when(data.getFile(file.getPathname())).thenReturn(file);
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor))).thenReturn(program);
    when(program.getDomainFile()).thenReturn(file);
    when(manager.getCurrentProgram()).thenReturn(program);
    when(manager.isVisible(program)).thenReturn(true);
    return program;
  }

  @Test
  void missingManagerAndCancellationPreventUiHandoff() throws Exception {
    assertThrows(
        GhidraMcpException.class, () -> support.openProgram(project, "/client.dll", null, monitor));
    PluginTool tool = mock(PluginTool.class);
    ProgramManager manager = mock(ProgramManager.class);
    DomainFile file = programFile("/client.dll");
    when(tool.getService(ProgramManager.class)).thenReturn(manager);
    when(data.getFile("/client.dll")).thenReturn(file);
    doThrow(new CancelledException()).when(monitor).checkCancelled();
    assertThrows(
        CancelledException.class, () -> support.openProgram(project, "/client.dll", tool, monitor));
  }

  @Test
  void identityReleasesTemporaryOwnershipEvenWhenMetadataReadFails() throws Exception {
    Program program = mock(Program.class);
    DomainFile file = programFile("/client.dll");
    when(data.getFile("/client.dll")).thenReturn(file);
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor))).thenReturn(program);
    when(program.getExecutableSHA256())
        .thenThrow(new IllegalStateException("metadata unavailable"));
    assertThrows(
        IllegalStateException.class, () -> support.binaryIdentity(project, "/client.dll", monitor));
    verify(program).release(any());
  }

  @Test
  void identityCanReadAnUnopenedProjectProgramWithoutUiServices() throws Exception {
    Program program = mock(Program.class);
    DomainFile file = programFile("/client.dll");
    when(data.getFile("/client.dll")).thenReturn(file);
    when(file.getDomainObject(any(), eq(false), eq(false), same(monitor))).thenReturn(program);
    when(program.getExecutableSHA256()).thenReturn("a".repeat(64));
    assertEquals("a".repeat(64), support.binaryIdentity(project, "/client.dll", monitor).sha256());
    verify(program).release(any());
  }

  private DomainFile programFile(String path) {
    DomainFile file = mock(DomainFile.class);
    when(file.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
    when(file.getPathname()).thenReturn(path);
    doReturn(Program.class).when(file).getDomainObjectClass();
    return file;
  }

  private ProgramLifecycleSupport importerReturning(LoadResults<Program> loaded) {
    return new ProgramLifecycleSupport() {
      @Override
      LoadResults<Program> load(
          Project project, Path source, String name, String folder, TaskMonitor monitor) {
        return loaded;
      }
    };
  }
}
