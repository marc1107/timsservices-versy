package aqua.blatt1.common.msgtypes;

import java.io.Serializable;
import java.net.InetSocketAddress;

@SuppressWarnings("serial")
public final class LocationRequest implements Serializable {
	private String fishId;
	
	public LocationRequest(String fishId) {
		this.fishId = fishId;
	}

	public String getFishId() {
		return this.fishId;
	}
}
