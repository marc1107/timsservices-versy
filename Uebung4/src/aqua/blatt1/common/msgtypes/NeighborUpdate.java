package aqua.blatt1.common.msgtypes;

import java.io.Serializable;
import java.net.InetSocketAddress;

@SuppressWarnings("serial")
public final class NeighborUpdate implements Serializable {
	private final InetSocketAddress leftAddress;
	private final InetSocketAddress rightAddress;

	public NeighborUpdate(InetSocketAddress leftAddress, InetSocketAddress rightAddress) {
		this.leftAddress = leftAddress;
		this.rightAddress = rightAddress;
	}

	public InetSocketAddress getLeftAddress() {
		return this.leftAddress;
	}
	
	public InetSocketAddress getRightAddress() {
		return this.rightAddress;
	}
}
