package com.github.skjolber.odc;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import org.h2.tools.Csv;
import org.h2.tools.SimpleResultSet;
import org.h2.tools.SimpleRowSource;

public class ReferenceSimpleRowSource implements SimpleRowSource {

	// https://stackoverflow.com/questions/26283618/h2-user-defined-function-is-called-many-times
	
	public static ResultSet forPath(Connection connection, String p) throws IOException, SQLException {
		SimpleRowSource source;
		if(connection.getMetaData().getURL().equals("jdbc:columnlist:connection")) {
			source = new EmptySimpleRowSource();
		} else {
			Path path = Paths.get(p);
			source = new ReferenceSimpleRowSource(path);
		}

		SimpleResultSet result = new SimpleResultSet(source);

        // must be uppercase 
        result.addColumn("CVEID", Types.VARCHAR, Integer.MAX_VALUE, 0);
        result.addColumn("NAME", Types.VARCHAR, Integer.MAX_VALUE, 0);
        result.addColumn("URL", Types.VARCHAR, Integer.MAX_VALUE, 0);
        result.addColumn("SOURCE", Types.VARCHAR, Integer.MAX_VALUE, 0);
        
        return result;
	}
	
	private DataInputStream in;
	private BinaryReference reference;

	public ReferenceSimpleRowSource(Path path) throws IOException {
		this.reference = new BinaryReference();
		
		this.in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)));
	}

	@Override
	public Object[] readRow() throws SQLException {
		try {
			if(!reference.read(in)) {
				return null;
			}
			return new Object[] {reference.getCveId(), reference.getName(), reference.getUrl(), reference.getSource()};
		} catch (IOException e) {
			e.printStackTrace();
			throw new SQLException(e);
		}
	}

	@Override
	public void close() {
		try {
			in.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void reset() throws SQLException {
		throw new SQLException("Not implemented");
	}
}
