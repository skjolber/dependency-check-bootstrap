package test;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Runner3 {

	public static final void main(String[] args) throws Exception {
		
		for(int i = 0; i < 1; i++) {
			System.out.println("***************************************************************************************************************************************************************************************************************************************");
			File file = new File("/tmp/testdb");
			file.delete();
			
			Path path = Paths.get("/home/skjolber/workspaces/dependencycheck/test/src/main/resources/gz");
			
			CsvTransformer3 transformer = new CsvTransformer3();
			
			transformer.process(path);
		}
	}
	
}
