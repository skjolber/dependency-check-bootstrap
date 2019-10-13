package test;



import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.LangString;
import org.owasp.dependencycheck.data.nvd.json.ProblemtypeDatum;

import com.opencsv.CSVWriter;

public class CweEntryWriter {

	private CSVWriter writer;
	private Path path;
	
	public CweEntryWriter(Path directory) {
		path = directory.resolve("owasp.cweEntry.csv");
	}	

    public void write(int vulnerabilityId, DefCveItem cve) {
    	String[] row = new String[] {Integer.toString(vulnerabilityId), null};
        for (ProblemtypeDatum datum : cve.getCve().getProblemtype().getProblemtypeData()) {
            for (LangString desc : datum.getDescription()) {
                if ("en".equals(desc.getLang())) {
                	row[1] = desc.getValue();
                	
                	writer.writeNext(row);
                }
            }
        }
    }

	public void open() throws IOException {
		writer = new CSVWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8));
		writer.writeNext(new String[]{"cveid", "cwe"});
	}
	
	public void close() throws IOException {
		if(writer != null) {
			writer.close(); 
		}
	}

	public String getSql()  {
		try {
			return String.format(IOUtils.toString(getClass().getResourceAsStream("/sql/cweEntry.sql"), StandardCharsets.UTF_8), path.toAbsolutePath().toString());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}	
}
