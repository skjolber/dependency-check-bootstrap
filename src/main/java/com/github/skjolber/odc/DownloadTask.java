package com.github.skjolber.odc;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.compress.utils.IOUtils;

public class DownloadTask implements Runnable {

	private ThreadPoolExecutor processExecutor;
	private GenerateCsvTask processTask;
	private Path destination;
	
	private URL source;
	
	public DownloadTask(URL source, Path destination, GenerateCsvTask processTask, ThreadPoolExecutor processExecutor) {
		super();
		this.source = source;
		this.destination = destination;
		this.processTask = processTask;
		this.processExecutor = processExecutor;
	}

	@Override
	public void run() {
		System.out.println("Run download task for " + source + " -> " + destination);
		try {
			try (OutputStream out = Files.newOutputStream(destination);
				 InputStream in = source.openStream();
					) {
				IOUtils.copy(in, out, 16 * 1024);
			}
			System.out.println("Downloaded " + source + " to " + destination);
			processExecutor.submit(processTask);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	
}
