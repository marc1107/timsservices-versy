package aqua.blatt1.broker;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/*
 * This class is not thread-safe and hence must be used in a thread-safe way, e.g. thread confined or 
 * externally synchronized. 
 */

public class ClientCollection<T> {
	private class Client {
		final String id;
		final T client;
		volatile Calendar leaseTimeStamp;

		Client(String id, Calendar leaseTimeStamp, T client) {
			this.id = id;
			this.leaseTimeStamp = leaseTimeStamp;
			this.client = client;
		}
	}

	private final List<Client> clients;

	public ClientCollection() {
		clients = new ArrayList<Client>();
	}

	public ClientCollection<T> add(String id, Calendar leaseTimeStamp, T client) {
		clients.add(new Client(id, leaseTimeStamp, client));
		return this;
	}

	public ClientCollection<T> remove(int index) {
		clients.remove(index);
		return this;
	}

	public int indexOf(String id) {
		for (int i = 0; i < clients.size(); i++)
			if (clients.get(i).id.equals(id))
				return i;
		return -1;
	}

	public int indexOf(T client) {
		for (int i = 0; i < clients.size(); i++)
			if (clients.get(i).client.equals(client))
				return i;
		return -1;
	}

	public T getClient(int index) {
		return clients.get(index).client;
	}

	public int size() {
		return clients.size();
	}

	public T getLeftNeighorOf(int index) {
		return index == 0 ? clients.get(clients.size() - 1).client : clients.get(index - 1).client;
	}

	public T getRightNeighorOf(int index) {
		return index < clients.size() - 1 ? clients.get(index + 1).client : clients.get(0).client;
	}
	
	public boolean containsClient(T client) {
		for (int i = 0; i < clients.size(); i++)
			if (clients.get(i).client.equals(client))
				return true;
		return false;
	}

	public synchronized void setLeaseTimeStamp(int index, Calendar leaseTimeStamp) {
		clients.get(index).leaseTimeStamp = leaseTimeStamp;
	}
	
	public synchronized Calendar getLeaseTimeStamp(int index) {
		return clients.get(index).leaseTimeStamp;
	}
	
	public String getClientId(int index) {
		return clients.get(index).id;	
	}
}
