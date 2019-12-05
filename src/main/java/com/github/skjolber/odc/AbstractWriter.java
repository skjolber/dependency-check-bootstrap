package com.github.skjolber.odc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.opencsv.CSVWriter;
import com.opencsv.ICSVWriter;

public class AbstractWriter {
	
	private boolean noop;
	
	public AbstractWriter(boolean noop) {
		super();
		this.noop = noop;
	}

	public ICSVWriter createWriter(Path path) throws IOException {
		if(noop) {
			return new NoopICSVWriter();
		}
		return new CSVWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8));
	}
}
