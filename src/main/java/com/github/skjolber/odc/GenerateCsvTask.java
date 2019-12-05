package com.github.skjolber.odc;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.io.FilenameUtils;
import org.owasp.dependencycheck.utils.Settings;

public class GenerateCsvTask implements Runnable {

	private ThreadPoolExecutor processExecutor;
	private IdSpace idSpace;
	private Settings settings;
	private ConnectionFactory connectionFactory;
	
	private URL source;
	private Path destination;
	
	private CpeCache cpes;
	private boolean noop;
	
	public GenerateCsvTask(URL source, Path destination, IdSpace idSpace, Settings settings,
			ConnectionFactory connectionFactory, ThreadPoolExecutor processExecutor, CpeCache cpes, boolean noop) {
		super();
		this.source = source;
		this.destination = destination;
		this.idSpace = idSpace;
		this.settings = settings;
		this.connectionFactory = connectionFactory;
		this.processExecutor = processExecutor;
		this.cpes = cpes;
		this.noop = noop;
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
			NvdCveParser parser = new NvdCveParser(destination, idSpace, settings, cpes, noop);
			
			parser.parse(source);
	
			if(!noop) {
				for(String sql : parser.getSql()) {
					processExecutor.submit(new InsertCsvTask(sql, connectionFactory));
				}
			}
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	public Path getDestination() {
		return destination;
	}
}
