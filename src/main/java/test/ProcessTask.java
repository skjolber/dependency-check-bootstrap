package test;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.io.FilenameUtils;
import org.owasp.dependencycheck.utils.Settings;

public class ProcessTask implements Runnable {

	private ThreadPoolExecutor processExecutor;
	private IdSpace idSpace;
	private Settings settings;
	private ConnectionFactory connectionFactory;
	
	private URL source;
	private Path destination;
	
	public ProcessTask(URL source, Path destination, IdSpace idSpace, Settings settings,
			ConnectionFactory connectionFactory, ThreadPoolExecutor processExecutor) {
		super();
		this.source = source;
		this.destination = destination;
		this.idSpace = idSpace;
		this.settings = settings;
		this.connectionFactory = connectionFactory;
		this.processExecutor = processExecutor;
	}

	public DownloadTask getDownloadTask() throws MalformedURLException {
		Path local = destination.resolve(FilenameUtils.getName(source.getPath()));
		
		URL localUrl = local.toUri().toURL();
		
		DownloadTask downloadTask = new DownloadTask(source, local, this, processExecutor);
		
		source = localUrl;
		
		return downloadTask;
	}
	
	@Override
	public void run() {
		try {
			NvdCveParser parser = new NvdCveParser(destination, idSpace, settings);
			
			parser.parse(source);
	
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
					System.out.println(source + " sql in " + (System.currentTimeMillis() - sqlTime));
				};
				processExecutor.submit(sqlTask);
			}
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	public Path getDestination() {
		return destination;
	}
}
