package test;

import java.io.File;
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

public class CsvTransformer {

	private Settings settings = new Settings();
	
	private final int downloadThreads;
	private final int processThreads;
	
	private ConnectionFactory connectionFactory;
	
	private ThreadPoolExecutor processExecutor;
	private ThreadPoolExecutor downloadExecutor;

	
	public CsvTransformer() throws Exception {
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
			
			int processWhileDownloading = Math.min(urls.size(), processThreads);
			
			for(int i = 0; i < processWhileDownloading; i++) {
				URL url = urls.get(i);

				Path resolve = destination.resolve(FilenameUtils.getName(url.getPath()));

			}
			
			// rest: download, then process
			for(int i = processWhileDownloading; i < urls.size(); i++) {
				URL url = urls.get(i);
			
				Path resolve = destination.resolve(FilenameUtils.getName(url.getPath()));

			}
			

			CpeCache cpeCache = new CpeCache();
			// last ned og parse 4
			// så submit nedlastning av resten
			// etter at prosesseringsjobber submitted
			
			IdSpace idSpace = new IdSpace(1, Integer.MAX_VALUE / 2, urls.size());
			
			VulnerabilityHandler handler = new VulnerabilityHandler(idSpace);

			try (Connection keepAliveConnection = connectionFactory.getConnection()) {
				
				List<Runnable> tasks = new ArrayList<>();

				List<Runnable> secondBatch = new ArrayList<>();

				for(URL url: urls) {
					
					tasks.add(() -> {
						try {
							Path resolve = destination.resolve(FilenameUtils.getName(url.getPath()));
							
							if(!Files.exists(resolve)) {
								Files.createDirectory(resolve);
							}
							
							System.out.println("Process " + url + " -> " + resolve);
			
							NvdCveParser parser = new NvdCveParser(resolve, idSpace, settings, cpeCache);
							
							parser.parse(url);

							List<String> sqls = parser.getSql();

							for(String sql : sqls) {
								Runnable sqlTask = () -> {

									long sqlTime = System.currentTimeMillis();
						            try (Connection conn = connectionFactory.getConnection()) {
						            	try (Statement statement = conn.createStatement()) {
						            		statement.execute(sql);
						            	}
						            } catch (SQLException e) {
						            	throw new RuntimeException(e);
									}
									System.out.println(url + " sql in " + (System.currentTimeMillis() - sqlTime));
								};
								processExecutor.submit(sqlTask);
							}

							synchronized(secondBatch) {
								if(!secondBatch.isEmpty()) {
									Runnable r = secondBatch.remove(secondBatch.size() - 1);
									processExecutor.submit(r);
								}
							}

						} catch(Exception e) {
							e.printStackTrace();
						}
					});
				}

				
				List<Runnable> subList = tasks.subList(0, Math.min(tasks.size(), downloadThreads));
				if(subList.size() < tasks.size()) {
					for(int i = subList.size(); i < tasks.size(); i++) {
						secondBatch.add(tasks.get(i));
					}
				}
				
				for(Runnable r : subList) {
					processExecutor.submit(r);
				}

				while (processExecutor.getActiveCount() > 0 || !processExecutor.getQueue().isEmpty()) {
					try {
						Thread.sleep(20);
					} catch (InterruptedException e) {
						break;
					}
		        }			
			}
			
            processExecutor.shutdown();
		}
		
		System.out.println("Ran in " + (System.currentTimeMillis() - time) / 1000 + "ms");
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
}
