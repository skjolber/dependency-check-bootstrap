package test;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
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

public class CsvTransformer3 {

	private Settings settings = new Settings();
	
	private final int downloadThreads;
	private final int processThreads;
	
	private ConnectionFactory connectionFactory;
	
	private ThreadPoolExecutor processExecutor;
	private ThreadPoolExecutor downloadExecutor;
	
	public CsvTransformer3() throws Exception {
		settings.setString(Settings.KEYS.DB_CONNECTION_STRING, "jdbc:h2:file:/tmp/testdb");
		settings.setString(Settings.KEYS.H2_DATA_DIRECTORY, "/tmp/testdb");
		this.connectionFactory = new ConnectionFactory();
		
		try (Connection connection = connectionFactory.getConnection()) {
			createTables(connection);
		}
		
		this.downloadThreads = Math.min(4, Runtime.getRuntime().availableProcessors());
		this.processThreads = Runtime.getRuntime().availableProcessors();
		
		this.processExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(processThreads);
		this.downloadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(downloadThreads);
	}
	
	public void process(Path source) throws Exception {
		long time = System.currentTimeMillis();
		Path destination = Paths.get("/tmp");
		
		try (Stream<Path> walk = Files.walk(source)) {

			/*
			List<Path> result = getFiles(walk);
			
			List<URL> urls = new ArrayList<>();
			for(Path path : result) {
				urls.add(path.toUri().toURL());
			}
			*/

			List<URL> urls = getUrls();
			
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
	
					ProcessTask task = new ProcessTask(url, d, idSpace, settings, connectionFactory, processExecutor, cpeCache);
					if(i < processWhileDownloading) {
						System.out.println("Process while downloading " + url);
						processExecutor.submit(task);
					} else {
						// rest: download, then process
						System.out.println("Download, then process " + url);
						downloadExecutor.submit(task.getDownloadTask());
					}
				}
				
				while (processExecutor.getActiveCount() > 0 || !processExecutor.getQueue().isEmpty() || downloadExecutor.getActiveCount() > 0 || !downloadExecutor.getQueue().isEmpty()) {
					try {
						Thread.sleep(20);
					} catch (InterruptedException e) {
						break;
					}
		        }			

			}
            long postProcess = System.currentTimeMillis();
            postProcessTables();
            
			while (processExecutor.getActiveCount() > 0 || !processExecutor.getQueue().isEmpty() || downloadExecutor.getActiveCount() > 0 || !downloadExecutor.getQueue().isEmpty()) {
				try {
					Thread.sleep(20);
				} catch (InterruptedException e) {
					break;
				}
	        }

            System.out.println("Post-processed in " + (System.currentTimeMillis() - postProcess));

            processExecutor.shutdown();
            downloadExecutor.shutdown();
			
		}
		
		
		
		System.out.println("Ran in " + (System.currentTimeMillis() - time) + "ms");
	}

	private List<URL> getUrls() throws MalformedURLException {
		List<URL> urls = new ArrayList<>();
		for(int i = 2005; i <= 2019; i++) {
			urls.add(new URL(String.format("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz", i)));
		}
		return urls;
	}

	private List<Path> getFiles(Stream<Path> walk) {
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
		return result;
	}
	
    private void createTables(Connection conn) throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/data/initialize2.sql")) {
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
    	List<String> sqls = IOUtils.readLines(getClass().getResourceAsStream("/data/constraints.sql"), StandardCharsets.UTF_8);
    	System.out.println("Got " + sqls.size() + " post-processing statements");
		long sqlTime = System.currentTimeMillis();
        try (Connection conn = connectionFactory.getConnection()) {
    		for(String sql : sqls) {
            	try (Statement statement = conn.createStatement()) {
            		statement.execute(sql);
            	}
    		}
        } catch (SQLException e) {
        	e.printStackTrace();
        	throw new RuntimeException(e);
		}
		System.out.println("Constraint in " + (System.currentTimeMillis() - sqlTime));
    }     
}
