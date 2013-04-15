package org.marl.hobes.ctx;

public class HobesResponse {

	private String requestSource;
	private Object requestContent;
	private Class<? extends HobesCommand> commandType;
	private Object content;
	
	
	
	public HobesResponse(String requestSource, Object requestContent,
			Class<? extends HobesCommand> commandType, Object content) {
		super();
		this.requestSource = requestSource;
		this.requestContent = requestContent;
		this.commandType = commandType;
		this.content = content;
	}
	
	public String getRequestSource() {
		return requestSource;
	}
	public Object getRequestContent() {
		return requestContent;
	}
	public String getCommandType() {
		return commandType.getName();
	}
	public Object getContent() {
		return content;
	}
	
}
