import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.AutoImporter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class BatchExtractOpCodes extends GhidraScript {

    // Update the input folder path to the one containing executable files
    private static final String INPUT_FOLDER_PATH = "Import Path"; //this is where i add my import folder path
    private static final String OUTPUT_FOLDER_PATH = "export path"; //this is where i add my export folder path

    @Override
    protected void run() throws Exception {
        // Import files from the specified folder
        importFilesFromFolder(INPUT_FOLDER_PATH);
        
        // Extract opcodes from all imported programs
        extractOpcodesForAllPrograms();
    }

    private void importFilesFromFolder(String folderPath) throws IOException {
        File folder = new File(folderPath);
        if (!folder.exists() || !folder.isDirectory()) {
            println("Invalid folder path: " + folderPath);
            return;
        }

        // Get the root folder of the current project using getProject()
        DomainFolder rootFolder = getProject().getProjectData().getRootFolder();

        for (File file : folder.listFiles()) {
            if (file.isFile()) {
                println("Importing: " + file.getAbsolutePath());
                // Use the appropriate import method
                AutoImporter.importByUsingBestGuess(file, getProject(), rootFolder.getName(), getMonitor());
                // Analyze the imported program
                analyzeImportedProgram(file);
            }
        }
    }

    private void analyzeImportedProgram(File file) {
        // Wait for the analysis to complete
        waitForAnalysisCompletion();

        // Extract opcodes for all programs
        extractOpcodesForAllPrograms();
    }

    private void waitForAnalysisCompletion() {
        // Implement logic to wait until the analysis is complete
        // This can include monitoring project tasks or simply sleeping for a set time
        // Here is a simple approach that you might want to replace with a proper check
        try {
            Thread.sleep(5000); // Wait for 5 seconds (adjust as necessary)
        } catch (InterruptedException e) {
            println("Interrupted while waiting for analysis to complete.");
        }
    }

    private void extractOpcodesForAllPrograms() throws IOException {
        DomainFile[] domainFiles = getProject().getProjectData().getAllDomainFiles();

        for (DomainFile domainFile : domainFiles) {
            if (domainFile.isProgram()) { // Directly check if the domainFile is a program
                Program program = (Program) domainFile.getDomainObject(this.getMonitor(), false, false);

                if (program != null) {
                    String outputFilePath = OUTPUT_FOLDER_PATH + File.separator + program.getName() + ".opcode";
                    extractOpcodes(program, outputFilePath);
                    program.release(this); // Release the program after processing
                }
            }
        }
    }

    private void extractOpcodes(Program program, String outputFilePath) {
        var listing = program.getListing();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            var instructions = listing.getInstructions(true);
            int instructionCount = 0;

            while (instructions.hasNext()) {
                var instruction = instructions.next();
                writer.write(instruction.toString());
                writer.newLine();
                instructionCount++;
            }

            println("Extracted " + instructionCount + " opcodes to " + outputFilePath);
        } catch (IOException e) {
            println("Error writing opcodes to file: " + e.getMessage());
        }
    }
}
