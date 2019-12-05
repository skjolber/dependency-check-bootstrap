package com.github.skjolber.odc;

import java.io.IOException;
import java.io.InputStream;
import java.lang.Thread.UncaughtExceptionHandler;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.utils.Settings;

public class CsvDatabaseGenerator implements UncaughtExceptionHandler {

	protected volatile Throwable uncaughtException = null;
	
	private Settings settings = new Settings();
	
	private final int downloadThreads;
	private final int processThreads;
	
	private ConnectionFactory connectionFactory;
	
	private ThreadPoolExecutor processExecutor;
	private ThreadPoolExecutor downloadExecutor;
	
	private boolean remote;
	private boolean multiThreaded;
	private boolean noop;
	
	public CsvDatabaseGenerator(boolean remote, boolean multiThreaded, boolean noop) throws Exception {
		this.remote = remote;
		this.multiThreaded = multiThreaded;
		this.noop = noop;
		
		settings.setString(Settings.KEYS.DB_CONNECTION_STRING, "jdbc:h2:file:/tmp/testdb;AUTOCOMMIT=ON;LOG=0;CACHE_SIZE=65536;UNDO_LOG=0;LOCK_MODE=0");
		settings.setString(Settings.KEYS.H2_DATA_DIRECTORY, "/tmp/testdb");
		this.connectionFactory = new ConnectionFactory();
		
		try (Connection connection = connectionFactory.getConnection()) {
			createTables(connection);
		}
		
		this.downloadThreads = multiThreaded ? Math.min(4, Runtime.getRuntime().availableProcessors()) : 1;
		this.processThreads = multiThreaded ? Runtime.getRuntime().availableProcessors() : 1;
		
		this.processExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(processThreads);
		this.processExecutor.setThreadFactory(new UncaughtExceptionHandlerThreadFactory(processExecutor.getThreadFactory(), this));
		
		this.downloadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(downloadThreads);
		this.downloadExecutor.setThreadFactory(new UncaughtExceptionHandlerThreadFactory(downloadExecutor.getThreadFactory(), this));		
	}
	
	public void process() throws Exception {
		long time = System.currentTimeMillis();
		
		Path destination = Paths.get("/tmp");
		
		List<URL> urls = remote ? getUrls() : getResources();
		
		IdSpace idSpace = new IdSpace(1, Integer.MAX_VALUE / 2, urls.size());

		int processWhileDownloading = Math.min(urls.size(), downloadThreads);
		
		CpeCache cpeCache = new CpeCache();
		
		try (Connection keepAliveConnection = connectionFactory.getConnection()) {
			for(int i = 0; i < urls.size(); i++) {
				URL url = urls.get(i);

				Path d = destination.resolve(FilenameUtils.getName(url.getPath()));

				if(!Files.exists(d)) {
					Files.createDirectory(d);
				}

				GenerateCsvTask task = new GenerateCsvTask(url, d, idSpace, settings, connectionFactory, processExecutor, cpeCache, noop);
				if(i < processWhileDownloading) {
					System.out.println("Process while downloading " + url);
					processExecutor.submit(task);
				} else {
					// rest: download, then process
					System.out.println("Download, then process " + url);
					downloadExecutor.submit(task.getDownloadTask());
				}
			}

			while (!processExecutor.isShutdown() && !downloadExecutor.isShutdown() && (processExecutor.getActiveCount() > 0 || !processExecutor.getQueue().isEmpty() || downloadExecutor.getActiveCount() > 0 || !downloadExecutor.getQueue().isEmpty())) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					break;
				}
	        }			

		}

        processExecutor.shutdown();
        downloadExecutor.shutdown();

        if(!noop) {
	        postProcessTables();
	
	        // database cleanup has zero effect, here
	        
	        // list results
	        String[] tables = new String[] {"software", "cpeEntry", "reference", "vulnerability", "properties", "cweEntry"};
	        
	        try (Connection conn = connectionFactory.getConnection()) {
	        	try (Statement statement = conn.createStatement()) {
	        		for(String table : tables) {
		        		ResultSet executeQuery = statement.executeQuery("SELECT COUNT(*) AS rows FROM " + table);
		        		executeQuery.next();
		        		int int1 = executeQuery.getInt("rows");
		        		System.out.println("Got " + int1 + " rows for " + table);
	        		}
	    		}
	        } catch (SQLException e) {
	        	throw new RuntimeException(e);
			}
        }
        
        if(uncaughtException != null) {
        	throw new RuntimeException("Underlying thread pool threw exception");
        }
		System.out.println("Ran in " + (System.currentTimeMillis() - time) + "ms");
	}

	private List<URL> getUrls() throws MalformedURLException {
		List<URL> urls = new ArrayList<>();
		for(int i = 2002; i <= 2019; i++) {
			urls.add(new URL(String.format("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz", i)));
		}
		return urls;
	}
	private List<URL> getResources() throws IOException {
		return getFiles(Paths.get("src", "main", "resources", "gz"));
	}

	private List<URL> getFiles(Path path) throws IOException {
		try (Stream<Path> walk = Files.walk(path)) {
			
			List<Path> result = walk.filter(f -> f.toString().endsWith(".gz")).collect(Collectors.toList());
			
			Collections.sort(result, new Comparator<Path>() {
	
				@Override
				public int compare(Path a, Path b) {
					FileChannel aFileChannel;
					try {
						aFileChannel = FileChannel.open(a);
						FileChannel bFileChannel = FileChannel.open(b);
						return -Long.compare(aFileChannel.size(), bFileChannel.size());
					} catch(IOException e) {
						throw new RuntimeException();
					}
				}
			});
			
			return result.stream().map(e -> {
				try {
					return e.toUri().toURL();
				} catch (MalformedURLException e1) {
					throw new RuntimeException(e1);
				}
			}) .collect(Collectors.toList());
		}
	}
	
    private void createTables(Connection conn) throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/csv-sql/initialize.sql")) {
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
    
    private void postProcessTables() throws Exception {
        long postProcess = System.currentTimeMillis();
        
    	List<String> sqls = IOUtils.readLines(getClass().getResourceAsStream("/csv-sql/constraints.sql"), StandardCharsets.UTF_8);
    	System.out.println("Got " + sqls.size() + " post-processing statements, running them in sequence");
        try (Connection conn = connectionFactory.getConnection()) {
    		for(String sql : sqls) {
            	try (Statement statement = conn.createStatement()) {
            		statement.execute(sql);
            	}
    		}
        }
        System.out.println("Post-processed in " + (System.currentTimeMillis() - postProcess));
    }     
    
	@Override
	public void uncaughtException(Thread t, Throwable e) {
		System.out.println("Uncaugth exception: " + t.toString());
		
		this.uncaughtException = e;
		
		e.printStackTrace(); 
		
        processExecutor.shutdown();
        downloadExecutor.shutdown();		
	}    
}
