package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FindingsSnapshot;
import com.themixednuts.models.FindingsSnapshot.*;
import com.themixednuts.utils.JsonMapperHolder;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
class FindingsTest {
  @TempDir Path temp;

  private FunctionFinding finding(
      String address,
      String bytes,
      String assembly,
      String code,
      boolean truncated,
      String status) {
    return new FunctionFinding(
        "f",
        address,
        "int f(void)",
        "USER_DEFINED",
        "comment",
        null,
        List.of(new InstructionFinding(address, "0", bytes, assembly)),
        List.of(),
        truncated,
        new Decompilation(status, code, null));
  }

  private FindingsSnapshot snapshot(FunctionFinding function) {
    return new FindingsSnapshot(
        1, "2026-10-07T00:00:00Z", 17, false, "test", null, List.of(function), List.of());
  }

  @Test
  void identicalFunctionsHaveNoObservedDifferences() {
    var a = snapshot(finding("1000", "c3", "RET", "void f() {}", false, "completed"));
    var comparison = FindingsReader.compare(a, a);
    assertTrue(comparison.signatureEqual());
    assertTrue(comparison.instructionBytesEqual());
    assertTrue(comparison.assemblyEqual());
    assertTrue(comparison.decompiledCodeEqual());
    assertTrue(comparison.observedDifferences().isEmpty());
  }

  @Test
  void pureEntryAddressShiftDoesNotBecomeAnInstructionDifference() {
    var a = snapshot(finding("1000", "c3", "RET", "void f() {}", false, "completed"));
    var b = snapshot(finding("2000", "c3", "RET", "void f() {}", false, "completed"));
    var result = FindingsReader.compare(a, b);
    assertEquals(List.of("entry_point"), result.observedDifferences());
    assertTrue(result.instructionBytesEqual());
    assertTrue(result.assemblyEqual());
  }

  @Test
  void realChangesAreObservedWithoutCompatibilityInference() {
    var a = snapshot(finding("1000", "c3", "RET", "return 1;", false, "completed"));
    var b = snapshot(finding("1000", "90", "NOP", "return 2;", false, "completed"));
    var result = FindingsReader.compare(a, b);
    assertEquals(
        List.of("instruction_bytes", "assembly", "decompiled_code"), result.observedDifferences());
    assertFalse(result.instructionBytesEqual());
    assertFalse(result.decompiledCodeEqual());
  }

  @Test
  void failedDecompilationAndPartialListingAreUnknownRatherThanEqual() {
    var a = snapshot(finding("1000", "c3", "RET", "return 1;", false, "completed"));
    var b = snapshot(finding("1000", "c3", "RET", null, true, "timeout"));
    var result = FindingsReader.compare(a, b);
    assertNull(result.instructionBytesEqual());
    assertNull(result.assemblyEqual());
    assertNull(result.decompiledCodeEqual());
    assertEquals(List.of("instruction_bytes", "assembly", "decompiled_code"), result.unknown());
  }

  @Test
  void exportIsVersionedAndDoesNotClobberAnExistingOrRacingFile() throws Exception {
    FindingsSupport support = new FindingsSupport();
    Path target = support.destination(temp.resolve("findings.json").toString(), false);
    var data = snapshot(finding("1000", "c3", "RET", "return 1;", false, "completed"));
    support.write(data, target, false, TaskMonitor.DUMMY);
    var json = JsonMapperHolder.getMapper().readTree(Files.readString(target));
    assertEquals(1, json.path("schema_version").asInt());
    assertEquals(17, json.path("modification_number").asInt());
    assertEquals("1000", json.path("functions").get(0).path("entry_point").asText());
    assertThrows(GhidraMcpException.class, () -> support.destination(target.toString(), false));
    String original = Files.readString(target);
    assertThrows(
        GhidraMcpException.class, () -> support.write(data, target, false, TaskMonitor.DUMMY));
    assertEquals(original, Files.readString(target));
    try (var files = Files.list(temp)) {
      assertEquals(1, files.count());
    }
  }

  @Test
  void explicitOverwritePublishesTheNewSnapshot() throws Exception {
    FindingsSupport support = new FindingsSupport();
    Path target = temp.resolve("findings.json");
    Files.writeString(target, "old");
    support.destination(target.toString(), true);
    support.write(
        snapshot(finding("2000", "c3", "RET", null, false, "failed")),
        target,
        true,
        TaskMonitor.DUMMY);
    var json = JsonMapperHolder.getMapper().readTree(Files.readString(target));
    assertEquals(
        "failed", json.path("functions").get(0).path("decompilation").path("status").asText());
  }

  @Test
  void cancelledExportPreservesExistingFileAndLeavesNoTemporaryFile() throws Exception {
    Path target = temp.resolve("findings.json");
    Files.writeString(target, "old");
    var monitor =
        new TaskMonitorAdapter(true) {
          private int checks;

          @Override
          public void checkCancelled() throws CancelledException {
            if (++checks == 2) throw new CancelledException();
          }
        };
    assertThrows(
        CancelledException.class,
        () ->
            new FindingsSupport()
                .write(
                    snapshot(finding("1000", "c3", "RET", null, false, "failed")),
                    target,
                    true,
                    monitor));
    assertEquals("old", Files.readString(target));
    try (var files = Files.list(temp)) {
      assertEquals(1, files.count());
    }
  }

  @Test
  void invalidDestinationsFailWithoutCreatingDirectories() {
    var support = new FindingsSupport();
    assertThrows(GhidraMcpException.class, () -> support.destination("relative.json", false));
    assertThrows(
        GhidraMcpException.class,
        () -> support.destination(temp.resolve("missing/file.json").toString(), false));
    assertThrows(GhidraMcpException.class, () -> support.destination(temp.toString(), true));
  }

  @Test
  void oversizedJsonFailsBeforePublishing() throws Exception {
    Path target = temp.resolve("findings.json");
    Files.writeString(target, "old");
    var data =
        snapshot(finding("1000", "c3", "RET", "x".repeat(9 * 1024 * 1024), false, "completed"));
    assertThrows(
        GhidraMcpException.class,
        () -> new FindingsSupport().write(data, target, true, TaskMonitor.DUMMY));
    assertEquals("old", Files.readString(target));
  }

  @Test
  void comparisonRequiresDifferentProgramsBeforeLoadingEither() {
    Project project = mock(Project.class);
    ProjectData data = mock(ProjectData.class);
    DomainFile file = mock(DomainFile.class);
    when(project.getProjectData()).thenReturn(data);
    when(data.getFile("/p")).thenReturn(file);
    doReturn(Program.class).when(file).getDomainObjectClass();
    assertThrows(
        GhidraMcpException.class,
        () ->
            new FindingsSupport()
                .compare(project, "/p", "1000", "/p", "2000", 1, TaskMonitor.DUMMY));
    verify(file, times(2)).getDomainObjectClass();
    verifyNoMoreInteractions(file);
  }

  @Test
  void snapshotIncludesSelectedStructureLayoutAndRetainsLockUntilCaptured() throws Exception {
    Program program = mock(Program.class);
    when(program.lock(anyString())).thenReturn(true);
    ProgramBasedDataTypeManager manager = mock(ProgramBasedDataTypeManager.class);
    when(program.getDataTypeManager()).thenReturn(manager);
    Structure structure = mock(Structure.class);
    DataTypeComponent field = mock(DataTypeComponent.class);
    DataType type = mock(DataType.class);
    when(manager.getDataType("/types/State")).thenReturn(structure);
    when(structure.getComponents()).thenReturn(new DataTypeComponent[] {field});
    when(structure.getNumComponents()).thenReturn(1);
    when(structure.getLength()).thenReturn(8);
    when(field.getOffset()).thenReturn(4);
    when(field.getLength()).thenReturn(4);
    when(field.getFieldName()).thenReturn("value");
    when(field.getDataType()).thenReturn(type);
    when(type.getPathName()).thenReturn("/int");
    var result =
        new FindingsReader()
            .read(program, List.of(), List.of("/types/State"), 1, TaskMonitor.DUMMY);
    var exported = result.structures().getFirst();
    assertEquals(8, exported.length());
    assertEquals(4, exported.fields().getFirst().offset());
    assertEquals("/int", exported.fields().getFirst().typePath());
    var order = inOrder(program, structure);
    order.verify(program).lock(anyString());
    order.verify(structure).getComponents();
    order.verify(program).unlock();
  }

  @Test
  void failedSnapshotReleasesLoadedProgramAndLock() throws Exception {
    Project project = mock(Project.class);
    ProjectData data = mock(ProjectData.class);
    DomainFile file = mock(DomainFile.class);
    Program program = mock(Program.class);
    when(project.getProjectData()).thenReturn(data);
    when(data.getFile("/p")).thenReturn(file);
    doReturn(Program.class).when(file).getDomainObjectClass();
    when(file.getDomainObject(any(), eq(false), eq(false), any())).thenReturn(program);
    when(program.lock(anyString())).thenReturn(true);
    assertThrows(
        GhidraMcpException.class,
        () ->
            new FindingsSupport()
                .capture(project, "/p", List.of(), List.of("relative"), 1, TaskMonitor.DUMMY));
    var order = inOrder(program);
    order.verify(program).unlock();
    order.verify(program).release(any());
  }

  @Test
  void busyProgramCannotProduceASnapshot() {
    Program program = mock(Program.class);
    assertThrows(
        GhidraMcpException.class,
        () -> new FindingsReader().read(program, List.of(), List.of(), 1, TaskMonitor.DUMMY));
    verify(program, never()).unlock();
    verify(program, never()).getListing();
  }

  @Test
  void functionReaderUsesExactEntryAndRetainsCommentsWhenDecompilationFails() throws Exception {
    Program program = mock(Program.class);
    FunctionManager manager = mock(FunctionManager.class);
    Function function = mock(Function.class);
    Listing listing = mock(Listing.class);
    CodeUnitIterator units = mock(CodeUnitIterator.class);
    Instruction instruction = mock(Instruction.class);
    var space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    Address entry = space.getAddress(0x1000);
    when(program.getAddressFactory())
        .thenReturn(new DefaultAddressFactory(new AddressSpace[] {space}));
    when(program.lock(anyString())).thenReturn(true);
    when(program.getFunctionManager()).thenReturn(manager);
    when(manager.getFunctionAt(entry)).thenReturn(function);
    when(function.getEntryPoint()).thenReturn(entry);
    when(function.getBody()).thenReturn(new AddressSet(entry));
    when(function.getName()).thenReturn("f");
    when(function.getPrototypeString(false, true)).thenReturn("void f(void)");
    when(program.getListing()).thenReturn(listing);
    when(listing.getCodeUnits(any(AddressSetView.class), eq(true))).thenReturn(units);
    when(units.hasNext()).thenReturn(true, false);
    when(units.next()).thenReturn(instruction);
    when(instruction.getAddress()).thenReturn(entry);
    when(instruction.getBytes()).thenReturn(new byte[] {(byte) 0xc3});
    when(instruction.toString()).thenReturn("RET");
    when(instruction.getComment(CommentType.EOL)).thenReturn("known comment");
    FindingsReader reader =
        new FindingsReader() {
          @Override
          Decompilation decompile(Program p, Function f, int timeout, TaskMonitor monitor) {
            return new Decompilation("failed", null, "test failure");
          }
        };
    var result =
        reader
            .read(program, List.of("1000"), List.of(), 1, TaskMonitor.DUMMY)
            .functions()
            .getFirst();
    assertEquals("c3", result.instructions().getFirst().bytes());
    assertEquals("0", result.instructions().getFirst().entryOffset());
    assertEquals("known comment", result.comments().getFirst().text());
    assertEquals("failed", result.decompilation().status());
    assertThrows(
        GhidraMcpException.class,
        () -> reader.read(program, List.of("1001"), List.of(), 1, TaskMonitor.DUMMY));
  }

  @Test
  void argumentValidationRunsBeforeAccessingTheActiveProject() {
    var tool = new FindingsTool();
    assertThrows(
        GhidraMcpException.class,
        () ->
            tool.execute(
                    null,
                    Map.of("action", "export_findings", "file_name", "p", "path", "out"),
                    null)
                .block());
    assertThrows(
        GhidraMcpException.class,
        () ->
            tool.execute(
                    null,
                    Map.of(
                        "action",
                        "export_findings",
                        "file_name",
                        "p",
                        "path",
                        "out",
                        "function_addresses",
                        List.of(1)),
                    null)
                .block());
    assertThrows(
        GhidraMcpException.class,
        () ->
            tool.execute(null, Map.of("action", "compare_function", "left_file_name", "p"), null)
                .block());
    assertThrows(
        GhidraMcpException.class,
        () -> tool.execute(null, Map.of("action", "invalid"), null).block());
  }
}
