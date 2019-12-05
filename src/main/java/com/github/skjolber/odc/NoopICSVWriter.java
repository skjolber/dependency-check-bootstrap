package com.github.skjolber.odc;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import com.opencsv.ICSVWriter;
import com.opencsv.ResultSetHelper;

public class NoopICSVWriter implements ICSVWriter {

	@Override
	public void close() throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void flush() throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeAll(Iterable<String[]> allLines, boolean applyQuotesToAll) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeAll(List<String[]> allLines, boolean applyQuotesToAll) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeAll(Iterable<String[]> allLines) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeAll(List<String[]> allLines) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public int writeAll(ResultSet rs, boolean includeColumnNames) throws SQLException, IOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int writeAll(ResultSet rs, boolean includeColumnNames, boolean trim) throws SQLException, IOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int writeAll(ResultSet rs, boolean includeColumnNames, boolean trim, boolean applyQuotesToAll)
			throws SQLException, IOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void writeNext(String[] nextLine, boolean applyQuotesToAll) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeNext(String[] nextLine) {
		if(nextLine == null || nextLine[0] == null) {
			throw new RuntimeException();
		}
	}

	@Override
	public boolean checkError() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setResultService(ResultSetHelper resultService) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void flushQuietly() {
		// TODO Auto-generated method stub
		
	}

}
