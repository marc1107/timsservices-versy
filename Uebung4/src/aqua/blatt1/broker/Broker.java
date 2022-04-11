package aqua.blatt1.broker;

import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.swing.JOptionPane;


import aqua.blatt1.common.Direction;
import aqua.blatt1.common.Properties;
import aqua.blatt1.common.msgtypes.DeregisterRequest;
import aqua.blatt1.common.msgtypes.HandoffRequest;
import aqua.blatt1.common.msgtypes.NeighborUpdate;
import aqua.blatt1.common.msgtypes.RegisterRequest;
import aqua.blatt1.common.msgtypes.RegisterResponse;
import aqua.blatt1.common.msgtypes.Token;
import messaging.Endpoint;
import messaging.Message;
import aqua.blatt2.broker.*;

public class Broker {
	private Endpoint endpoint;
	private volatile Thread killThread;
	private volatile ClientCollection<InetSocketAddress> collection;
	private volatile boolean runningFlag;

	public Broker() {	
		this.endpoint = new Endpoint(Properties.PORT);
		this.collection = new ClientCollection<>();
		this.runningFlag = true;
		this.killThread = new Thread(new Runnable() {
			@Override
			public void run() {
				JOptionPane.showMessageDialog(null, "Press OK button to stop server");
				runningFlag = false;
			}
		});
		this.killThread.start();
	}
	
	public void broker() {
		ExecutorService executor = Executors.newFixedThreadPool(10);
		while(this.runningFlag) {
			Message msg = this.endpoint.nonBlockingReceive();
			if(msg == null) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				continue;
			}
			if(msg.getPayload() instanceof PoisonPill) 
				break;
			executor.execute(new BrokerTask(msg));
		}
		executor.shutdown();
		
		if(this.killThread.isAlive()) {
			this.killThread.interrupt();		
		}
		
		System.out.println("Broker stopped");
	}
	
	
	public static void main(String[] args) {
		Broker broker = new Broker();
		broker.broker();
	}
	
	public class BrokerTask implements Runnable {
		Message message;
		ReadWriteLock lock; 
		
		private BrokerTask(Message msg) {
			this.message = msg;
			this.lock = new ReentrantReadWriteLock();
		}

		@Override
		public void run() {
			var payload = this.message.getPayload();
			
			if(this.message.getPayload() instanceof RegisterRequest) {
				register(this.message.getSender());
			} else if(this.message.getPayload() instanceof DeregisterRequest) {
				DeregisterRequest dr = (DeregisterRequest) payload;
				deregister(dr.getId());
			} else if(this.message.getPayload() instanceof HandoffRequest) {
				System.out.println("HandOf received");
				HandoffRequest hor = (HandoffRequest) payload;
				handoffFish(hor, this.message.getSender());
			} 
		}
		
		private synchronized void register(InetSocketAddress addr) {
			String id = "tank" + (Broker.this.collection.size() + 1);
			Broker.this.collection.add(id, addr);
			
			if(Broker.this.collection.size() == 1) {
				Broker.this.endpoint.send(addr, new Token());
			}
			
						
			int index = Broker.this.collection.indexOf(id);
			InetSocketAddress rightNeighbor = Broker.this.collection.getRightNeighorOf(index);
			InetSocketAddress leftNeighbor = Broker.this.collection.getLeftNeighorOf(index);
			
			Broker.this.endpoint.send(leftNeighbor, new NeighborUpdate(null, addr));
			Broker.this.endpoint.send(rightNeighbor, new NeighborUpdate(addr, null));
			Broker.this.endpoint.send(addr, new NeighborUpdate(leftNeighbor, rightNeighbor));
			Broker.this.endpoint.send(addr, new RegisterResponse(id));
		}
		
		private synchronized void deregister(String id) {
			int index = Broker.this.collection.indexOf(id);
			InetSocketAddress rightNeighbor = Broker.this.collection.getRightNeighorOf(index);
			InetSocketAddress leftNeighbor = Broker.this.collection.getLeftNeighorOf(index);
			
			Broker.this.endpoint.send(leftNeighbor, new NeighborUpdate(null, rightNeighbor));
			Broker.this.endpoint.send(rightNeighbor, new NeighborUpdate(leftNeighbor, null));
			
			Broker.this.collection.remove(Broker.this.collection.indexOf(id));
		}
		
		private void handoffFish(HandoffRequest hor, InetSocketAddress addr) {
			this.lock.readLock().lock();
			int currentFishTankIndex = Broker.this.collection.indexOf(addr);
			this.lock.readLock().unlock();
			
			InetSocketAddress nextClient;
			if(hor.getFish().getDirection() == Direction.LEFT) {
				this.lock.readLock().lock();
				nextClient = Broker.this.collection.getLeftNeighorOf(currentFishTankIndex);
				this.lock.readLock().unlock();
			}
			else {
				this.lock.readLock().lock();
				nextClient = Broker.this.collection.getRightNeighorOf(currentFishTankIndex);
				this.lock.readLock().unlock();
			}
			
			Broker.this.endpoint.send(nextClient, hor);
		}
	}
}
