package test;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Runner {

	public static final void main(String[] args) throws Exception {
		
		File file = new File("/tmp/testdb");
		file.delete();
		
		Path path = Paths.get("/home/skjolber/workspaces/dependencycheck/test/src/main/resources/gz");
		
		CsvTransformer transformer = new CsvTransformer();
		
		transformer.process(path);
	}
	
}
