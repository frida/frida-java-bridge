package re.frida;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class Script {
	private long handle;
	private LinkedBlockingQueue<String> pending = new LinkedBlockingQueue<>();

	public Script(String sourceCode) {
		handle = create(sourceCode);
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			destroy(handle);
		} finally {
			super.finalize();
		}
	}

	public String getNextMessage() {
		try {
			return pending.poll(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			return getNextMessage();
		}
	}

	private void onMessage(String message) {
		pending.add(message);
	}

	private native long create(String sourceCode);
	private native void destroy(long handle);
}
