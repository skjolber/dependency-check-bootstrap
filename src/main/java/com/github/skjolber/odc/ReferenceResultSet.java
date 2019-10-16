package com.github.skjolber.odc;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLType;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Calendar;
import java.util.Map;

import javax.sql.rowset.RowSetMetaDataImpl;

public class ReferenceResultSet implements ResultSet {

	public static ReferenceResultSet forPath(String p) throws IOException {
		System.out.println("New resultset for " + p);
		Path path = Paths.get(p);
		return new ReferenceResultSet(new DataInputStream(new BufferedInputStream(Files.newInputStream(path))));
	}
	
	private DataInputStream in;
	private BinaryReference reference;

	public ReferenceResultSet(DataInputStream in) {
		this.reference = new BinaryReference();
		this.in = in;
	}

	@Override
	public <T> T unwrap(Class<T> iface) throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isWrapperFor(Class<?> iface) throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean next() throws SQLException {
		try {
			return reference.read(in);
		} catch(IOException e) {
			e.printStackTrace();
			throw new SQLException(e);
		}
	}

	@Override
	public void close() throws SQLException {
		try {
			in.close();
		} catch (IOException e) {
			throw new SQLException(e);
		}
	}

	@Override
	public boolean wasNull() throws SQLException {
		return false;
	}

	@Override
	public String getString(int columnIndex) throws SQLException {
		switch(columnIndex) {
		case 2: return reference.getName();
		case 3: return reference.getUrl();
		case 4: return reference.getSource();
		default : {
			throw new SQLException("Unexpected column " + columnIndex);
		}
		}
	}

	@Override
	public boolean getBoolean(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public byte getByte(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public short getShort(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public int getInt(int columnIndex) throws SQLException {
		switch(columnIndex) {
		case 1: return reference.getCveId();
		default : {
			throw new SQLException("Unexpected column " + columnIndex);
		}
		}
	}

	@Override
	public long getLong(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public float getFloat(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public double getDouble(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public BigDecimal getBigDecimal(int columnIndex, int scale) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public byte[] getBytes(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public Date getDate(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public Time getTime(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public Timestamp getTimestamp(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public InputStream getAsciiStream(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public InputStream getUnicodeStream(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public InputStream getBinaryStream(int columnIndex) throws SQLException {
		throw new SQLException("Unexpected column " + columnIndex);
	}

	@Override
	public String getString(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public boolean getBoolean(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public byte getByte(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public short getShort(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public int getInt(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public long getLong(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public float getFloat(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public double getDouble(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public BigDecimal getBigDecimal(String columnLabel, int scale) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public byte[] getBytes(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public Date getDate(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public Time getTime(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public Timestamp getTimestamp(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public InputStream getAsciiStream(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public InputStream getUnicodeStream(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public InputStream getBinaryStream(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected column label " + columnLabel);
	}

	@Override
	public SQLWarning getWarnings() throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public void clearWarnings() throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public String getCursorName() throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public ResultSetMetaData getMetaData() throws SQLException {
		RowSetMetaDataImpl impl = new RowSetMetaDataImpl();
		
		//throw new SQLException("Unexpected method call");
		
		impl.setColumnCount(4);
		
		impl.setColumnName(1, "cveid");
		impl.setColumnName(2, "name");
		impl.setColumnName(3, "url");
		impl.setColumnName(4, "source");

		impl.setColumnLabel(1, "cveid");
		impl.setColumnLabel(2, "name");
		impl.setColumnLabel(3, "url");
		impl.setColumnLabel(4, "source");
		
		impl.setColumnType(1, Types.INTEGER);
		impl.setColumnType(2, Types.VARCHAR);
		impl.setColumnType(3, Types.VARCHAR);
		impl.setColumnType(4, Types.VARCHAR);

		impl.setColumnTypeName(1, "INTEGER");
		impl.setColumnTypeName(2, "VARCHAR");
		impl.setColumnTypeName(3, "VARCHAR");
		impl.setColumnTypeName(4, "VARCHAR");
		
		impl.setPrecision(1, 10);
		impl.setPrecision(2, Integer.MAX_VALUE);
		impl.setPrecision(3, Integer.MAX_VALUE);
		impl.setPrecision(4, Integer.MAX_VALUE);
		
		impl.setScale(1, 0);
		impl.setScale(2, 0);
		impl.setScale(3, 0);
		impl.setScale(4, 0);
		
		return impl;
	}

	@Override
	public Object getObject(int columnIndex) throws SQLException {
		switch(columnIndex) {
			case 1: return reference.getCveId();
			case 2: return reference.getName();
			case 3: return reference.getUrl();
			case 4: return reference.getSource();
			default : {
				throw new SQLException("Unexpected column " + columnIndex);
			}
		}
	}

	@Override
	public Object getObject(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public int findColumn(String columnLabel) throws SQLException {
		throw new SQLException("Unexpected method call");
	}

	@Override
	public Reader getCharacterStream(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Reader getCharacterStream(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public BigDecimal getBigDecimal(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public BigDecimal getBigDecimal(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isBeforeFirst() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isAfterLast() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isFirst() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isLast() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void beforeFirst() throws SQLException {


	}

	@Override
	public void afterLast() throws SQLException {


	}

	@Override
	public boolean first() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean last() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public int getRow() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean absolute(int row) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean relative(int rows) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean previous() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void setFetchDirection(int direction) throws SQLException {


	}

	@Override
	public int getFetchDirection() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void setFetchSize(int rows) throws SQLException {
		System.out.println("setFetchSize");
	}

	@Override
	public int getFetchSize() throws SQLException {
		System.out.println("getFetchSize");

		throw new SQLException("Unexpected method call");
	}

	@Override
	public int getType() throws SQLException {
		System.out.println("getType");
		throw new SQLException("Unexpected method call");
	}

	@Override
	public int getConcurrency() throws SQLException {
		System.out.println("getConcurrency");
		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean rowUpdated() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean rowInserted() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean rowDeleted() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateNull(int columnIndex) throws SQLException {


	}

	@Override
	public void updateBoolean(int columnIndex, boolean x) throws SQLException {


	}

	@Override
	public void updateByte(int columnIndex, byte x) throws SQLException {


	}

	@Override
	public void updateShort(int columnIndex, short x) throws SQLException {


	}

	@Override
	public void updateInt(int columnIndex, int x) throws SQLException {


	}

	@Override
	public void updateLong(int columnIndex, long x) throws SQLException {


	}

	@Override
	public void updateFloat(int columnIndex, float x) throws SQLException {


	}

	@Override
	public void updateDouble(int columnIndex, double x) throws SQLException {


	}

	@Override
	public void updateBigDecimal(int columnIndex, BigDecimal x) throws SQLException {


	}

	@Override
	public void updateString(int columnIndex, String x) throws SQLException {


	}

	@Override
	public void updateBytes(int columnIndex, byte[] x) throws SQLException {


	}

	@Override
	public void updateDate(int columnIndex, Date x) throws SQLException {


	}

	@Override
	public void updateTime(int columnIndex, Time x) throws SQLException {


	}

	@Override
	public void updateTimestamp(int columnIndex, Timestamp x) throws SQLException {


	}

	@Override
	public void updateAsciiStream(int columnIndex, InputStream x, int length) throws SQLException {


	}

	@Override
	public void updateBinaryStream(int columnIndex, InputStream x, int length) throws SQLException {


	}

	@Override
	public void updateCharacterStream(int columnIndex, Reader x, int length) throws SQLException {


	}

	@Override
	public void updateObject(int columnIndex, Object x, int scaleOrLength) throws SQLException {


	}

	@Override
	public void updateObject(int columnIndex, Object x) throws SQLException {


	}

	@Override
	public void updateNull(String columnLabel) throws SQLException {


	}

	@Override
	public void updateBoolean(String columnLabel, boolean x) throws SQLException {


	}

	@Override
	public void updateByte(String columnLabel, byte x) throws SQLException {


	}

	@Override
	public void updateShort(String columnLabel, short x) throws SQLException {


	}

	@Override
	public void updateInt(String columnLabel, int x) throws SQLException {


	}

	@Override
	public void updateLong(String columnLabel, long x) throws SQLException {


	}

	@Override
	public void updateFloat(String columnLabel, float x) throws SQLException {


	}

	@Override
	public void updateDouble(String columnLabel, double x) throws SQLException {


	}

	@Override
	public void updateBigDecimal(String columnLabel, BigDecimal x) throws SQLException {


	}

	@Override
	public void updateString(String columnLabel, String x) throws SQLException {


	}

	@Override
	public void updateBytes(String columnLabel, byte[] x) throws SQLException {


	}

	@Override
	public void updateDate(String columnLabel, Date x) throws SQLException {


	}

	@Override
	public void updateTime(String columnLabel, Time x) throws SQLException {


	}

	@Override
	public void updateTimestamp(String columnLabel, Timestamp x) throws SQLException {


	}

	@Override
	public void updateAsciiStream(String columnLabel, InputStream x, int length) throws SQLException {


	}

	@Override
	public void updateBinaryStream(String columnLabel, InputStream x, int length) throws SQLException {


	}

	@Override
	public void updateCharacterStream(String columnLabel, Reader reader, int length) throws SQLException {


	}

	@Override
	public void updateObject(String columnLabel, Object x, int scaleOrLength) throws SQLException {


	}

	@Override
	public void updateObject(String columnLabel, Object x) throws SQLException {


	}

	@Override
	public void insertRow() throws SQLException {


	}

	@Override
	public void updateRow() throws SQLException {


	}

	@Override
	public void deleteRow() throws SQLException {


	}

	@Override
	public void refreshRow() throws SQLException {


	}

	@Override
	public void cancelRowUpdates() throws SQLException {


	}

	@Override
	public void moveToInsertRow() throws SQLException {


	}

	@Override
	public void moveToCurrentRow() throws SQLException {


	}

	@Override
	public Statement getStatement() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Object getObject(int columnIndex, Map<String, Class<?>> map) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Ref getRef(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Blob getBlob(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Clob getClob(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Array getArray(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Object getObject(String columnLabel, Map<String, Class<?>> map) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Ref getRef(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Blob getBlob(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Clob getClob(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Array getArray(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Date getDate(int columnIndex, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Date getDate(String columnLabel, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Time getTime(int columnIndex, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Time getTime(String columnLabel, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Timestamp getTimestamp(int columnIndex, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Timestamp getTimestamp(String columnLabel, Calendar cal) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public URL getURL(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public URL getURL(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateRef(int columnIndex, Ref x) throws SQLException {


	}

	@Override
	public void updateRef(String columnLabel, Ref x) throws SQLException {


	}

	@Override
	public void updateBlob(int columnIndex, Blob x) throws SQLException {


	}

	@Override
	public void updateBlob(String columnLabel, Blob x) throws SQLException {


	}

	@Override
	public void updateClob(int columnIndex, Clob x) throws SQLException {


	}

	@Override
	public void updateClob(String columnLabel, Clob x) throws SQLException {


	}

	@Override
	public void updateArray(int columnIndex, Array x) throws SQLException {


	}

	@Override
	public void updateArray(String columnLabel, Array x) throws SQLException {


	}

	@Override
	public RowId getRowId(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public RowId getRowId(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateRowId(int columnIndex, RowId x) throws SQLException {


	}

	@Override
	public void updateRowId(String columnLabel, RowId x) throws SQLException {


	}

	@Override
	public int getHoldability() throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public boolean isClosed() throws SQLException {
		
		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateNString(int columnIndex, String nString) throws SQLException {


	}

	@Override
	public void updateNString(String columnLabel, String nString) throws SQLException {


	}

	@Override
	public void updateNClob(int columnIndex, NClob nClob) throws SQLException {


	}

	@Override
	public void updateNClob(String columnLabel, NClob nClob) throws SQLException {


	}

	@Override
	public NClob getNClob(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public NClob getNClob(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public SQLXML getSQLXML(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public SQLXML getSQLXML(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateSQLXML(int columnIndex, SQLXML xmlObject) throws SQLException {


	}

	@Override
	public void updateSQLXML(String columnLabel, SQLXML xmlObject) throws SQLException {


	}

	@Override
	public String getNString(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public String getNString(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Reader getNCharacterStream(int columnIndex) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public Reader getNCharacterStream(String columnLabel) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public void updateNCharacterStream(int columnIndex, Reader x, long length) throws SQLException {


	}

	@Override
	public void updateNCharacterStream(String columnLabel, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateAsciiStream(int columnIndex, InputStream x, long length) throws SQLException {


	}

	@Override
	public void updateBinaryStream(int columnIndex, InputStream x, long length) throws SQLException {


	}

	@Override
	public void updateCharacterStream(int columnIndex, Reader x, long length) throws SQLException {


	}

	@Override
	public void updateAsciiStream(String columnLabel, InputStream x, long length) throws SQLException {


	}

	@Override
	public void updateBinaryStream(String columnLabel, InputStream x, long length) throws SQLException {


	}

	@Override
	public void updateCharacterStream(String columnLabel, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateBlob(int columnIndex, InputStream inputStream, long length) throws SQLException {


	}

	@Override
	public void updateBlob(String columnLabel, InputStream inputStream, long length) throws SQLException {


	}

	@Override
	public void updateClob(int columnIndex, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateClob(String columnLabel, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateNClob(int columnIndex, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateNClob(String columnLabel, Reader reader, long length) throws SQLException {


	}

	@Override
	public void updateNCharacterStream(int columnIndex, Reader x) throws SQLException {


	}

	@Override
	public void updateNCharacterStream(String columnLabel, Reader reader) throws SQLException {


	}

	@Override
	public void updateAsciiStream(int columnIndex, InputStream x) throws SQLException {


	}

	@Override
	public void updateBinaryStream(int columnIndex, InputStream x) throws SQLException {


	}

	@Override
	public void updateCharacterStream(int columnIndex, Reader x) throws SQLException {


	}

	@Override
	public void updateAsciiStream(String columnLabel, InputStream x) throws SQLException {


	}

	@Override
	public void updateBinaryStream(String columnLabel, InputStream x) throws SQLException {


	}

	@Override
	public void updateCharacterStream(String columnLabel, Reader reader) throws SQLException {


	}

	@Override
	public void updateBlob(int columnIndex, InputStream inputStream) throws SQLException {


	}

	@Override
	public void updateBlob(String columnLabel, InputStream inputStream) throws SQLException {


	}

	@Override
	public void updateClob(int columnIndex, Reader reader) throws SQLException {


	}

	@Override
	public void updateClob(String columnLabel, Reader reader) throws SQLException {


	}

	@Override
	public void updateNClob(int columnIndex, Reader reader) throws SQLException {


	}

	@Override
	public void updateNClob(String columnLabel, Reader reader) throws SQLException {


	}

	@Override
	public <T> T getObject(int columnIndex, Class<T> type) throws SQLException {

		throw new SQLException("Unexpected method call");
	}

	@Override
	public <T> T getObject(String columnLabel, Class<T> type) throws SQLException {

		throw new SQLException("Unexpected method call");
	}



}
