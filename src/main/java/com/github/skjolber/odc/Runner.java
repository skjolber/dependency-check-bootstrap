package com.github.skjolber.odc;

import java.io.File;

public class Runner {

	public static final void main(String[] args) throws Exception {
		
		for(int i = 0; i < 1; i++) {
			System.out.println("***************************************************************************************************************************************************************************************************************************************");
			File file = new File("/tmp/testdb.trace.db");
			file.delete();
			file = new File("/tmp/testdb.mv.db");
			file.delete();
			
			CsvDatabaseGenerator transformer = new CsvDatabaseGenerator(false);
			transformer.process();
		}
	}
	
}
