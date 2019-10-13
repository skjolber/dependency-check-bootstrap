package test;

import java.util.concurrent.atomic.AtomicInteger;

public class IdSpace {

	private static class Bounds implements IdGenerator {
		
		private int max;
		private int min;
		private int current;

		public Bounds(int min, int max) {
			super();
			this.min = min;
			this.max = max;
			if(min < 0) {
				throw new RuntimeException();
			}
			this.current = min;
		}
		public int next() {
			current++;
			if(current > max) {
				throw new RuntimeException(current + " > " + max);
			}
			if(current < 0) {
				throw new RuntimeException();
			}
			return current;
		}
		
		public void validate() {
			if(current < min || current > max) {
				throw new IllegalStateException();
			}
		}
	}
	
	private final AtomicInteger current;
	private final int step;
	private final int max;
	
	public IdSpace(int from, int to, int count) {
		this.current = new AtomicInteger(from);
		this.step = (to - from) / count;
		this.max = to;
	}
	
	public IdGenerator next() {
		int start = current.getAndAdd(step);
		
		int end = start + step;
		if(end > max) {
			throw new IllegalArgumentException();
		}
		Bounds bound = new Bounds(start, end);
		
		return bound;
	}
	
}
