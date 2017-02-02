package re.frida;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class HookTest {
	@Test
	public void propagatesExceptions() {
		Script script = new Script("send('w00t');");
		assertEquals("w00t", script.getNextMessage());
	}
}
