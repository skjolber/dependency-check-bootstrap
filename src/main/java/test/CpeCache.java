package test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class CpeCache {

	private Map<String, Integer> cpes = new HashMap<>();
	private AtomicInteger counter = new AtomicInteger(1);
	
	public int get(String key) {
    	int id;
    	synchronized(cpes) {
	    	Integer integer = cpes.get(key);
	    	if(integer != null) {
	    		return integer;
	    	}
	
	    	id = counter.getAndIncrement();

	    	if(cpes.put(key, id) != null) {
	    		throw new RuntimeException();
	    	}
    	}
    	return -id;
	}
	
}
