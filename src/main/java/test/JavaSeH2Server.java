package test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class JavaSeH2Server {

    public static void main(String[] args) {

        String url = "jdbc:h2:file:/tmp/testdb";
        String user = "sa";
        String passwd = "s$cret";

        try (Connection con = DriverManager.getConnection(url, user, passwd)) {
        		long time = System.currentTimeMillis();
        		createTables(con);
        		System.out.println((System.currentTimeMillis()) - time + " ms");
        } catch (Exception ex) {
        	System.out.flush();
        	System.err.flush();
        	ex.printStackTrace();
        }
    }
    
    private static void createTables(Connection conn) throws Exception {

        try (InputStream is = getResourceAsStream("initialize2.sql")) {
            final String dbStructure = IOUtils.toString(is, StandardCharsets.UTF_8);

            Statement statement = null;
            try {
                statement = conn.createStatement();
                statement.execute(dbStructure);
            } catch (SQLException ex) {
                throw new RuntimeException(ex);
            } finally {
                statement.close();
            }
        }
    }    
    
    /**
     * Returns a File object for the given resource. The resource is attempted
     * to be loaded from the class loader.
     *
     * @param resource path
     * @return the file reference for the resource
     */
    public static File getResourceAsFile(final String resource) {
        final ClassLoader classLoader = FileUtils.class.getClassLoader();
        final String path = classLoader != null
                ? classLoader.getResource(resource).getFile()
                : ClassLoader.getSystemResource(resource).getFile();

        if (path == null) {
            return new File(resource);
        }
        return new File(path);
    }    
    
    public static InputStream getResourceAsStream(String resource) throws FileNotFoundException {
        final ClassLoader classLoader = FileUtils.class.getClassLoader();
        final InputStream inputStream = classLoader != null
                ? classLoader.getResourceAsStream(resource)
                : ClassLoader.getSystemResourceAsStream(resource);

        if (inputStream == null) {
        	return new FileInputStream(resource);
        }
        return inputStream;
    }    
}