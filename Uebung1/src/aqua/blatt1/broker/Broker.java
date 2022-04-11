package aqua.blatt1.broker;

import java.net.InetSocketAddress;

import aqua.blatt1.client.ClientCommunicator;
import aqua.blatt1.client.TankModel;
import aqua.blatt1.common.Direction;
import aqua.blatt1.common.FishModel;
import aqua.blatt1.common.Properties;
import aqua.blatt1.common.msgtypes.DeregisterRequest;
import aqua.blatt1.common.msgtypes.HandoffRequest;
import aqua.blatt1.common.msgtypes.RegisterRequest;
import aqua.blatt1.common.msgtypes.RegisterResponse;
import messaging.Endpoint;
import messaging.Message;

public class Broker {
	private Endpoint endpoint;
	private ClientCollection<InetSocketAddress> collection;

	public Broker() {	
		this.endpoint = new Endpoint(Properties.PORT);
		this.collection = new ClientCollection<>();
	}
	
	public void broker() {
		while(true) {
			Message msg = this.endpoint.blockingReceive();
			var payload = msg.getPayload();
			
			if(msg.getPayload() instanceof RegisterRequest) {
				register(msg.getSender());
			} else if(msg.getPayload() instanceof DeregisterRequest) {
				DeregisterRequest dr = (DeregisterRequest) payload;
				deregister(dr.getId());
			} else if(msg.getPayload() instanceof HandoffRequest) {
				HandoffRequest hor = (HandoffRequest) payload;
				handoffFish(hor, msg.getSender());
			}
		}
	}
	
	private void register(InetSocketAddress addr) {
		String id = "tank" + (this.collection.size() + 1);
		this.collection.add(id, addr);
		this.endpoint.send(addr, new RegisterResponse(id));
	}
	
	private void deregister(String id) {
		this.collection.remove(this.collection.indexOf(id));
	}
	
	private void handoffFish(HandoffRequest hor, InetSocketAddress addr) {
		int currentFishTankIndex = this.collection.indexOf(addr);
		
		InetSocketAddress nextClient;
		if(hor.getFish().getDirection() == Direction.LEFT) {
			nextClient = this.collection.getLeftNeighorOf(currentFishTankIndex);
		}
		else {
			nextClient = this.collection.getRightNeighorOf(currentFishTankIndex);
		}
		
		this.endpoint.send(nextClient, hor);
	}
	
	public static void main(String[] args) {
		Broker broker = new Broker();
		broker.broker();
	}
}
