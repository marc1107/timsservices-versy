package aqua.blatt1.common.msgtypes;

import java.io.Serializable;
import java.net.InetSocketAddress;

import aqua.blatt1.common.FishModel;

@SuppressWarnings("serial")
public final class LocationUpdate implements Serializable {
	private String fishId;
	
	public LocationUpdate(String fishId) {
		this.fishId = fishId;
	}
	
	public String getFishId() {
		return this.fishId;
	}
}
