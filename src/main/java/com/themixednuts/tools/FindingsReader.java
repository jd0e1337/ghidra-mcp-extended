package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FindingsSnapshot;
import com.themixednuts.models.FindingsSnapshot.*;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraAddressParser;
import com.themixednuts.utils.ProgramMetadataReader;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** Ghidra adapter for bounded, modification-locked snapshots. */
class FindingsReader {
  static final int MAX_SELECTION = 25;
  static final int MAX_LISTING = 2000;
  private static final int MAX_FIELDS = 1000;
  private static final int MAX_TEXT = 1_000_000;

  FindingsSnapshot read(
      Program program,
      List<String> addresses,
      List<String> structurePaths,
      int timeout,
      TaskMonitor monitor)
      throws Exception {
    if (!program.lock("MCP findings snapshot")) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("capture findings", "Program is being modified; retry when idle."));
    }
    try {
      monitor.checkCancelled();
      Budget budget = new Budget();
      List<FunctionFinding> functions = new ArrayList<>();
      for (String address : addresses) {
        monitor.checkCancelled();
        var entry = GhidraAddressParser.parse(program, address, "function_addresses");
        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null)
          throw invalid("function_addresses", address, "must be an exact function entry point");
        functions.add(function(program, function, timeout, monitor, budget));
      }
      List<StructureFinding> structures = new ArrayList<>();
      for (String path : structurePaths) {
        monitor.checkCancelled();
        if (!path.startsWith("/"))
          throw invalid("structure_paths", path, "must be an absolute data type path");
        var type = program.getDataTypeManager().getDataType(path);
        if (!(type instanceof Structure structure))
          throw invalid("structure_paths", path, "does not identify a structure");
        if (structure.getNumComponents() > MAX_FIELDS)
          throw invalid("structure_paths", path, "exceeds 1000 components");
        List<FieldFinding> fields = new ArrayList<>();
        for (var field : structure.getComponents()) {
          monitor.checkCancelled();
          var bit = field.getDataType() instanceof BitFieldDataType b ? b : null;
          fields.add(
              new FieldFinding(
                  field.getOrdinal(),
                  field.getOffset(),
                  field.getLength(),
                  budget.text(field.getFieldName()),
                  budget.text(field.getDataType().getPathName()),
                  budget.text(field.getComment()),
                  bit == null ? null : bit.getDeclaredBitSize(),
                  bit == null ? null : bit.getBitOffset()));
        }
        structures.add(
            new StructureFinding(
                path,
                structure.getLength(),
                structure.getAlignment(),
                structure.isPackingEnabled(),
                budget.text(structure.getDescription()),
                fields));
      }
      return new FindingsSnapshot(
          1,
          Instant.now().toString(),
          program.getModificationNumber(),
          program.isChanged(),
          "ghidra_program_database_current_state",
          ProgramMetadataReader.readIdentity(program),
          functions,
          structures);
    } finally {
      program.unlock();
    }
  }

  private FunctionFinding function(
      Program program, Function function, int timeout, TaskMonitor monitor, Budget budget)
      throws Exception {
    List<InstructionFinding> instructions = new ArrayList<>();
    List<CommentFinding> comments = new ArrayList<>();
    var units = program.getListing().getCodeUnits(function.getBody(), true);
    int count = 0;
    while (units.hasNext() && count < MAX_LISTING) {
      monitor.checkCancelled();
      var unit = units.next();
      count++;
      if (unit instanceof ghidra.program.model.listing.Instruction instruction) {
        instructions.add(
            new InstructionFinding(
                instruction.getAddress().toString(),
                Long.toString(instruction.getAddress().subtract(function.getEntryPoint())),
                budget.text(HexFormat.of().formatHex(instruction.getBytes())),
                budget.text(instruction.toString())));
      }
      for (CommentType type : CommentType.values()) {
        String text = unit.getComment(type);
        if (text != null)
          comments.add(
              new CommentFinding(unit.getAddress().toString(), type.name(), budget.text(text)));
      }
    }
    boolean truncated = units.hasNext();
    var decompiled = decompile(program, function, timeout, monitor);
    budget.text(decompiled.code());
    budget.text(decompiled.message());
    return new FunctionFinding(
        budget.text(function.getName()),
        function.getEntryPoint().toString(),
        budget.text(function.getPrototypeString(false, true)),
        function.getSignatureSource() == null ? null : function.getSignatureSource().toString(),
        budget.text(function.getComment()),
        budget.text(function.getRepeatableComment()),
        instructions,
        comments,
        truncated,
        decompiled);
  }

  Decompilation decompile(Program program, Function function, int timeout, TaskMonitor monitor)
      throws Exception {
    DecompInterface decompiler = new DecompInterface();
    try {
      if (!decompiler.openProgram(program)) {
        return new Decompilation("failed", null, decompiler.getLastMessage());
      }
      var result = decompiler.decompileFunction(function, timeout, monitor);
      monitor.checkCancelled();
      if (result == null
          || !result.decompileCompleted()
          || result.getDecompiledFunction() == null) {
        return new Decompilation(
            result != null && result.isTimedOut() ? "timeout" : "failed",
            null,
            result == null ? "No decompilation result" : result.getErrorMessage());
      }
      return new Decompilation(
          "completed", result.getDecompiledFunction().getC(), result.getErrorMessage());
    } catch (Exception e) {
      monitor.checkCancelled();
      if (e instanceof ghidra.util.exception.CancelledException) throw e;
      return new Decompilation(
          "failed", null, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    } finally {
      decompiler.dispose();
    }
  }

  static Comparison compare(FindingsSnapshot left, FindingsSnapshot right) {
    var a = left.functions().getFirst();
    var b = right.functions().getFirst();
    List<String> differences = new ArrayList<>();
    List<String> unknown = new ArrayList<>();
    if (!Objects.equals(a.entryPoint(), b.entryPoint())) differences.add("entry_point");
    Boolean signature = equality("signature", a.signature(), b.signature(), differences, unknown);
    boolean full =
        !a.listingTruncated()
            && !b.listingTruncated()
            && !a.instructions().isEmpty()
            && !b.instructions().isEmpty();
    Boolean bytes =
        equality(
            "instruction_bytes",
            full ? bytes(a) : null,
            full ? bytes(b) : null,
            differences,
            unknown);
    Boolean assembly =
        equality(
            "assembly", full ? assembly(a) : null, full ? assembly(b) : null, differences, unknown);
    Boolean code =
        equality(
            "decompiled_code",
            completed(a) ? a.decompilation().code() : null,
            completed(b) ? b.decompilation().code() : null,
            differences,
            unknown);
    return new Comparison(
        1,
        left,
        right,
        signature,
        bytes,
        assembly,
        code,
        differences,
        unknown,
        "Exact observations only. Entry addresses are excluded from instruction equality; embedded"
            + " addresses and relocation bytes are not normalized. No semantic equivalence or ABI"
            + " compatibility is inferred.");
  }

  private static List<String> bytes(FunctionFinding f) {
    // Retain instruction boundaries and relative placement, but ignore the absolute entry address.
    return f.instructions().stream().map(i -> i.entryOffset() + ":" + i.bytes()).toList();
  }

  private static List<String> assembly(FunctionFinding f) {
    return f.instructions().stream().map(i -> i.entryOffset() + ":" + i.text()).toList();
  }

  private static boolean completed(FunctionFinding f) {
    return "completed".equals(f.decompilation().status());
  }

  private static Boolean equality(
      String field, Object a, Object b, List<String> differences, List<String> unknown) {
    if (a == null || b == null) {
      unknown.add(field);
      return null;
    }
    boolean equal = a.equals(b);
    if (!equal) differences.add(field);
    return equal;
  }

  private static GhidraMcpException invalid(String arg, String value, String reason) {
    return new GhidraMcpException(GhidraMcpError.invalid(arg, value, reason));
  }

  private static class Budget {
    int used;

    String text(String value) {
      if (value != null) {
        used += value.length();
        if (used > MAX_TEXT)
          throw invalid(
              "selection",
              "text",
              "snapshot exceeds 1,000,000 text characters; select fewer findings");
      }
      return value;
    }
  }
}
