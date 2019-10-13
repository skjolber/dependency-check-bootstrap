package com.github.skjolber.odc;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.owasp.dependencycheck.data.nvdcve.DriverLoadException;
import org.owasp.dependencycheck.data.nvdcve.DriverLoader;

public class ConnectionFactory {

	private java.sql.Driver driver;

	public ConnectionFactory() throws DriverLoadException {
		driver = DriverLoader.load("org.h2.Driver");
	}
	
	public Connection getConnection() throws SQLException {
        String url = "jdbc:h2:file:/tmp/testdb";
        String user = "";
        String passwd = "";

        File file = new File("/tmp/testdb");
        file.delete();
        
        return DriverManager.getConnection(url, user, passwd);
    }
    
    public void cleanup() {
        DriverLoader.cleanup(driver);
    }
}