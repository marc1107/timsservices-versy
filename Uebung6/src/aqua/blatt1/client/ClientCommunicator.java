package aqua.blatt1.client;

import java.net.InetSocketAddress;
import java.util.Timer;
import java.util.TimerTask;

import messaging.Endpoint;
import messaging.Message;
import aqua.blatt1.client.TankModel.RecordingMode;
import aqua.blatt1.common.Direction;
import aqua.blatt1.common.FishModel;
import aqua.blatt1.common.Properties;
import aqua.blatt1.common.msgtypes.CollectSnapshot;
import aqua.blatt1.common.msgtypes.DeregisterRequest;
import aqua.blatt1.common.msgtypes.HandoffRequest;
import aqua.blatt1.common.msgtypes.LocationRequest;
import aqua.blatt1.common.msgtypes.LocationUpdate;
import aqua.blatt1.common.msgtypes.NameResolutionRequest;
import aqua.blatt1.common.msgtypes.NameResolutionResponse;
import aqua.blatt1.common.msgtypes.NeighborUpdate;
import aqua.blatt1.common.msgtypes.RegisterRequest;
import aqua.blatt1.common.msgtypes.RegisterResponse;
import aqua.blatt1.common.msgtypes.SnapshotMarker;
import aqua.blatt1.common.msgtypes.Token;

public class ClientCommunicator {
	private final Endpoint endpoint;

	public ClientCommunicator() {
		endpoint = new Endpoint();
	}

	public class ClientForwarder {
		private final InetSocketAddress broker;

		private ClientForwarder() {
			this.broker = new InetSocketAddress(Properties.HOST, Properties.PORT);
		}

		public void register() {
			endpoint.send(broker, new RegisterRequest());
		}

		public void deregister(String id) {
			endpoint.send(broker, new DeregisterRequest(id));
		}
		
		public void forwardToken(InetSocketAddress addr) {
			endpoint.send(addr, new Token());
		}

		public void sendSnapshotMarker(InetSocketAddress addr) {
			endpoint.send(addr, new SnapshotMarker());
		}
		
		public void sendSnapshotCollectionMarker(InetSocketAddress addr, CollectSnapshot cs) {
			endpoint.send(addr, cs);
		}
		
		public void sendLocationRequest(InetSocketAddress addr, String fishId) {
			endpoint.send(addr, new LocationRequest(fishId));
		}
		
		public void sendNameResolutionRequest(String tankId, String fishId) {
			endpoint.send(broker, new NameResolutionRequest(tankId, fishId));
		}
		
		public void sendLocationUpdate(InetSocketAddress addr, String fishId) {
			endpoint.send(addr, new LocationUpdate(fishId));
		}
		
		public void handOff(FishModel fish, TankModel tankModel) {
			if (fish.getDirection() == Direction.LEFT)
				endpoint.send(tankModel.leftNeighbor, new HandoffRequest(fish));
			else 
				endpoint.send(tankModel.rightNeighbor, new HandoffRequest(fish));
		}
	}

	public class ClientReceiver extends Thread {
		private final TankModel tankModel;
		
		private ClientReceiver(TankModel tankModel) {
			this.tankModel = tankModel;
		}

		@Override
		public void run() {
			while (!isInterrupted()) {
				Message msg = endpoint.blockingReceive();

				if (msg.getPayload() instanceof RegisterResponse) {
					RegisterResponse rr = (RegisterResponse) msg.getPayload();
					tankModel.onRegistration(rr.getId());
					
					Timer timer = new Timer(true);
					timer.schedule(new TimerTask() {
						@Override
						public void run() {
							tankModel.forwarder.register();
							if(timer != null) 
								timer.cancel();				
						}
					}, rr.getLeaseTime() - 1000);
				}

				if (msg.getPayload() instanceof HandoffRequest)
					tankModel.receiveFish(((HandoffRequest) msg.getPayload()).getFish());
				
				if (msg.getPayload() instanceof Token)
					tankModel.receiveToken();
				
				if (msg.getPayload() instanceof NeighborUpdate) {
					NeighborUpdate neighborUpdate = (NeighborUpdate) msg.getPayload();
					if (neighborUpdate.getLeftAddress() != null)
						tankModel.leftNeighbor = neighborUpdate.getLeftAddress();
					if (neighborUpdate.getRightAddress() != null)
						tankModel.rightNeighbor = neighborUpdate.getRightAddress();
				}			
				if (msg.getPayload() instanceof SnapshotMarker) {
					if (msg.getSender().equals(tankModel.leftNeighbor))
						tankModel.handleReceivedMarker("left");
					
					else
						tankModel.handleReceivedMarker("right");
				}				
	
				if (msg.getPayload() instanceof CollectSnapshot) {
					tankModel.hasSnapshotCollectToken = true;
					tankModel.snapshotCollector = (CollectSnapshot) msg.getPayload();
					if (tankModel.isInitiator) {
						tankModel.isSnapshotDone = true;
						tankModel.hasSnapshotCollectToken = false;
						tankModel.isInitiator = false;
					} else {
						tankModel.hasSnapshotCollectToken = false;
						tankModel.snapshotCollector.addFishies(tankModel.localState);
						tankModel.forwarder.sendSnapshotCollectionMarker(tankModel.leftNeighbor, tankModel.snapshotCollector);
					}
				}
				if (msg.getPayload() instanceof LocationRequest) {
					this.tankModel.locateFishLocally(((LocationRequest)msg.getPayload()).getFishId());
				}
				if (msg.getPayload() instanceof NameResolutionResponse) { 
					NameResolutionResponse lr = (NameResolutionResponse) msg.getPayload();
					this.tankModel.forwarder.sendLocationUpdate(lr.getAddress(), lr.getRequestId());
				}
				if (msg.getPayload() instanceof LocationUpdate) { 
					LocationUpdate lr = (LocationUpdate) msg.getPayload();
					this.tankModel.homeAgent.put(lr.getFishId(), msg.getSender());
				}
	
			}
			System.out.println("Receiver stopped.");
		}
	}

	public ClientForwarder newClientForwarder() {
		return new ClientForwarder();
	}

	public ClientReceiver newClientReceiver(TankModel tankModel) {
		return new ClientReceiver(tankModel);
	}

}
