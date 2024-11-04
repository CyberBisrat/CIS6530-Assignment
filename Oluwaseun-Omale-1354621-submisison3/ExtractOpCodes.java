import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.PrintWriter;
import java.io.File;
import java.io.IOException;

public class ExtractOpCodes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Program program = getCurrentProgram();
        Listing listing = program.getListing();

        // Get the program name and remove any file extension
        String programName = program.getName();
        int lastDotIndex = programName.lastIndexOf(".");
        if (lastDotIndex != -1) {
            programName = programName.substring(0, lastDotIndex);
        }

        // Set the file name with ".opcode" extension
        String fileName = programName + ".opcode";

        // Try to write the opcodes to the output file
        try (PrintWriter writer = new PrintWriter(new File(fileName))) {
            for (Function function : listing.getFunctions(true)) {
                for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
                    writer.println(instruction.toString());
                }
            }
            println("Opcodes extracted to " + fileName);
        } catch (IOException e) {
            printerr("Failed to write opcodes to file: " + e.getMessage());
        }
    }
}
