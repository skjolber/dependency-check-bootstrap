package com.github.skjolber.odc;

import java.io.File;

public class Runner {

	public static final void main(String[] args) throws Exception {
		
		for(int i = 0; i < 1; i++) {
			System.out.println("***************************************************************************************************************************************************************************************************************************************");
			File file = new File("/tmp/testdb");
			file.delete();
			
			CsvDatabaseGenerator transformer = new CsvDatabaseGenerator();
			
			transformer.process();
		}
	}
	
}
