package test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.compress.utils.IOUtils;

public class DownloadTask implements Runnable {

	private ThreadPoolExecutor processExecutor;
	private ProcessTask processTask;
	
	private URL source;
	
	public DownloadTask(URL source, Path destination, ProcessTask processTask, ThreadPoolExecutor processExecutor) {
		super();
		this.source = source;
		this.processTask = processTask;
		this.processExecutor = processExecutor;
	}

	@Override
	public void run() {
		try {
			try (OutputStream out = Files.newOutputStream(processTask.getDestination());
				 InputStream in = source.openStream();
					) {
				IOUtils.copy(in, out, 16 * 1024);
			}
			processExecutor.submit(processTask);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	
}
