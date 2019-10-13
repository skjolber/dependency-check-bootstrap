package test;

import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.ThreadPoolExecutor;

public class ProcessTask implements Runnable {

	private ThreadPoolExecutor processExecutor;
	
	private URL source;
	private Path destination;
	
	private IdSpace idSpace;
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}

	public Path getDestination() {
		return destination;
	}
}
