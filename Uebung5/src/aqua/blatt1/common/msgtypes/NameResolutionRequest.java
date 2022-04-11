package aqua.blatt1.common.msgtypes;

import java.io.Serializable;
import java.net.InetSocketAddress;

@SuppressWarnings("serial")
public final class NameResolutionRequest implements Serializable {
	private String tankId;
	private String requestId;
	
	
	public NameResolutionRequest(String tankId, String requestId) {
		this.tankId = tankId;
		this.requestId = requestId;
	}
	
	public String getRequestId() {
		return this.requestId;
	}
	
	public String getTankId() {
		return this.tankId;
	}
}
