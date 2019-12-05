package com.github.skjolber.odc;

import java.io.File;

public class Runner {

	public static final void main(String[] args) throws Exception {
		Thread.sleep(20000);
		for(int i = 0; i < 100; i++) {
			System.out.println("***************************************************************************************************************************************************************************************************************************************");
			File file = new File("/tmp/testdb.trace.db");
			file.delete();
			file = new File("/tmp/testdb.mv.db");
			file.delete();
			
			boolean remote = false; // if false it reads from local files
			boolean multiThreaded = false;
			boolean skipCSVs = false;
			
			CsvDatabaseGenerator transformer = new CsvDatabaseGenerator(remote, multiThreaded, skipCSVs);
			transformer.process();
		}
	}
	
}
