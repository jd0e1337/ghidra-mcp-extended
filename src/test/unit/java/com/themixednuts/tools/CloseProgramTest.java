package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.themixednuts.exceptions.GhidraMcpException;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
class CloseProgramTest {
  private final ProgramLifecycleSupport lifecycle = new ProgramLifecycleSupport();
  private Project project;
  private ProgramManager manager;
  private Program program;
  private PluginTool tool;

  @BeforeEach
  void setUp() {
    project = mock(Project.class);
    ProjectData data = mock(ProjectData.class);
    DomainFile file = mock(DomainFile.class);
    manager = mock(ProgramManager.class);
    program = mock(Program.class);
    tool = mock(PluginTool.class);
    when(project.getProjectData()).thenReturn(data);
    when(data.getFile("/client.dll")).thenReturn(file);
    doReturn(Program.class).when(file).getDomainObjectClass();
    when(file.getName()).thenReturn("client.dll");
    when(file.getPathname()).thenReturn("/client.dll");
    when(tool.getService(ProgramManager.class)).thenReturn(manager);
    when(program.getDomainFile()).thenReturn(file);
    when(manager.getAllOpenPrograms()).thenReturn(new Program[] {program});
    when(program.addConsumer(any())).thenReturn(true);
    when(program.lock(anyString())).thenReturn(true);
  }

  @Test
  void unchangedProgramClosesAndOwnershipOutlivesLock() throws Exception {
    when(manager.getAllOpenPrograms()).thenReturn(new Program[] {program}, new Program[0]);
    when(manager.closeProgram(program, true)).thenReturn(true);
    assertEquals(
        "closed",
        lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY).get("status"));
    var order = inOrder(program, manager);
    order.verify(program).lock(anyString());
    order.verify(program).isChanged();
    order.verify(program).isTemporary();
    order.verify(manager).closeProgram(program, true);
    order.verify(program).unlock();
    order.verify(program).release(any());
  }

  @Test
  void unsavedProgramsAreRejectedWithoutCloseOrSave() {
    when(program.isChanged()).thenReturn(true);
    assertThrows(
        GhidraMcpException.class,
        () -> lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY));
    verify(manager, never()).closeProgram(any(), anyBoolean());
    verify(program).unlock();
    verify(program).release(any());
  }

  @Test
  void temporaryProgramsAreRejectedEvenWhenIsChangedIsFalse() {
    when(program.isTemporary()).thenReturn(true);
    assertThrows(
        GhidraMcpException.class,
        () -> lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY));
    verify(manager, never()).closeProgram(any(), anyBoolean());
    verify(program).unlock();
    verify(program).release(any());
  }

  @Test
  void inProgressModificationDoesNotForceClose() {
    when(program.lock(anyString())).thenReturn(false);
    assertThrows(
        GhidraMcpException.class,
        () -> lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY));
    verify(manager, never()).closeProgram(any(), anyBoolean());
    verify(program, never()).unlock();
    verify(program).release(any());
  }

  @Test
  void falseCloseResultAndStillRegisteredProgramsDoNotReportSuccess() {
    assertThrows(
        GhidraMcpException.class,
        () -> lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY));
    when(manager.closeProgram(program, true)).thenReturn(true);
    assertThrows(
        GhidraMcpException.class,
        () -> lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY));
    verify(program, times(2)).unlock();
    verify(program, times(2)).release(any());
  }

  @Test
  void alreadyClosedProgramIsNotLoadedAgain() throws Exception {
    when(manager.getAllOpenPrograms()).thenReturn(new Program[0]);
    assertEquals(
        "already_closed",
        lifecycle.closeProgram(project, "/client.dll", tool, TaskMonitor.DUMMY).get("status"));
    verify(program, never()).addConsumer(any());
  }
}
