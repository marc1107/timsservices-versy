package aqua.blatt1.common.msgtypes;

import java.io.Serializable;
import java.net.InetSocketAddress;

@SuppressWarnings("serial")
public final class NameResolutionResponse implements Serializable {
	private InetSocketAddress addr;
	private String requestId;
	
	
	public NameResolutionResponse(InetSocketAddress addr, String requestId) {
		this.addr = addr;
		this.requestId = requestId;
	}
	
	public String getRequestId() {
		return this.requestId;
	}
	
	public InetSocketAddress getAddress() {
		return this.addr;
	}
}
