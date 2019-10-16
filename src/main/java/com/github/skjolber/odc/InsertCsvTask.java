package com.github.skjolber.odc;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class InsertCsvTask implements Runnable {

	private final String sql;
	private ConnectionFactory connectionFactory;

	public InsertCsvTask(String sql, ConnectionFactory connectionFactory) {
		super();
		this.sql = sql;
		this.connectionFactory = connectionFactory;
	}

	@Override
	public void run() {
        try (Connection conn = connectionFactory.getConnection()) {
        	try (Statement statement = conn.createStatement()) {
        		statement.execute(sql);
        	}
        } catch (SQLException e) {
        	e.printStackTrace();
        	
        	
        	throw new RuntimeException(e);
		}
	}

}
