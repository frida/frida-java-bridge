package re.frida;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.json.JSONException;
import org.json.JSONObject;

public class Script implements Closeable {
    private long handle;
    private LinkedBlockingQueue<String> pending = new LinkedBlockingQueue<>();

    public Script(String sourceCode) {
        handle = create(sourceCode);
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    @Override
    public void close() throws IOException {
        if (handle != 0) {
            destroy(handle);
            handle = 0;
        }
    }

    public String getNextMessage() {
        try {
            String message = pending.poll(5, TimeUnit.SECONDS);
            if (message == null) {
                throw new IllegalStateException("timed out waiting for a message from the"
                        + " script; see stderr and logcat for errors raised by it");
            }
            return message;
        } catch (InterruptedException e) {
            return getNextMessage();
        }
    }

    private void onMessage(String rawMessage) {
        try {
            JSONObject message = new JSONObject(rawMessage);

            String type = message.getString("type");
            if (type.equals("send")) {
                pending.add(message.getString("payload"));
            } else if (type.equals("log")) {
                System.out.println(message.getString("payload"));
            } else if (type.equals("error")) {
                // Not every error carries a stack, and getString() would throw right past it.
                System.err.println(message.optString("stack", rawMessage));
            } else {
                System.err.println(rawMessage);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private native long create(String sourceCode);
    private native void destroy(long handle);
}
