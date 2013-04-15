package org.marl.hobes.ctx;

public class EchoCommand implements HobesCommand {

	@Override
	public Object execute(String source, Object request) {
		return request;
	}

}
