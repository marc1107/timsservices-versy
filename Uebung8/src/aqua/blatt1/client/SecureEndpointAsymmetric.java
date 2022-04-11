package aqua.blatt1.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;

import aqua.blatt1.common.msgtypes.KeyExchangeMessage;
import messaging.Endpoint;
import messaging.Message;

public class SecureEndpointAsymmetric extends Endpoint {
	
	private KeyPair keyPair;
	private Map<InetSocketAddress, Cipher> knownKeys;
	
	private Cipher decryptCipher;
	
	public SecureEndpointAsymmetric(int port) {
		super(port);
		setupCrypt();	
	}

	public SecureEndpointAsymmetric() {
		super();
		setupCrypt();
	}
	
	private void setupCrypt() {
		this.knownKeys = new HashMap<>();
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(4096);
			this.keyPair = generator.generateKeyPair();
			
			this.decryptCipher = Cipher.getInstance("RSA");
			this.decryptCipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
		} catch (Exception e) {
			e.printStackTrace();
		}	
	}
	
	@Override
	public void send(InetSocketAddress receiver, Serializable payload) {
		if (!this.knownKeys.containsKey(receiver)) {
			super.send(receiver, new KeyExchangeMessage(this.keyPair.getPublic()));
			while(!this.knownKeys.containsKey(receiver)) {}
		}
		SealedObject sealedPayload = null;
		try {
			sealedPayload = new SealedObject(payload, this.knownKeys.get(receiver));
			super.send(receiver, sealedPayload);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public Message blockingReceive() {
		Message encodedMessage = super.blockingReceive();
		
		if (encodedMessage.getPayload() instanceof SealedObject) {
			SealedObject sealedPayload = (SealedObject) encodedMessage.getPayload();
			Serializable payload = null;
			try {
				payload = (Serializable) sealedPayload.getObject(this.decryptCipher);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return new Message(payload, encodedMessage.getSender());
		}
		else if (encodedMessage.getPayload() instanceof KeyExchangeMessage) {
			KeyExchangeMessage keyMsg = (KeyExchangeMessage) encodedMessage.getPayload();
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, keyMsg.getKey());
				this.knownKeys.put(encodedMessage.getSender(), cipher);
				super.send(encodedMessage.getSender(), new KeyExchangeMessage(this.keyPair.getPublic()));
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
				e.printStackTrace();
			} 
		}
		return null;
	}
	
	@Override
	public Message nonBlockingReceive() {
		Message encodedMessage = super.nonBlockingReceive();
		if (encodedMessage == null)
			return null;
		if (encodedMessage.getPayload() instanceof SealedObject) {
			SealedObject sealedPayload = (SealedObject) encodedMessage.getPayload();
			Serializable payload = null;
			try {
				payload = (Serializable) sealedPayload.getObject(this.decryptCipher);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return new Message(payload, encodedMessage.getSender());
		}
		else if (encodedMessage.getPayload() instanceof KeyExchangeMessage) {
			KeyExchangeMessage keyMsg = (KeyExchangeMessage) encodedMessage.getPayload();
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, keyMsg.getKey());
				this.knownKeys.put(encodedMessage.getSender(), cipher);
				super.send(encodedMessage.getSender(), new KeyExchangeMessage(this.keyPair.getPublic()));
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
				e.printStackTrace();
			} 
		}
		return null;
	}
}
