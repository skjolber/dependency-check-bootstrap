package com.github.skjolber.odc;

import java.sql.SQLException;

import org.h2.tools.SimpleRowSource;

public class EmptySimpleRowSource implements SimpleRowSource {

	@Override
	public Object[] readRow() throws SQLException {
		return null;
	}

	@Override
	public void close() {
	}

	@Override
	public void reset() throws SQLException {
	}

}
