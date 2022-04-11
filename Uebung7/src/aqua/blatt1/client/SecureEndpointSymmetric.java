package aqua.blatt1.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;
import messaging.Endpoint;
import messaging.Message;

public class SecureEndpointSymmetric extends Endpoint {
	
	private SecretKeySpec symetricKeySpec;
	private Cipher encryptCipher;
	private Cipher decryptCipher;
	
	public SecureEndpointSymmetric(int port) {
		super(port);
		setupCrypt();	
	}

	public SecureEndpointSymmetric() {
		super();
		setupCrypt();
	}
	
	private void setupCrypt() {
		this.symetricKeySpec = new SecretKeySpec("CAFEBABECAFEBABE".getBytes(), "AES");
		try {
			this.encryptCipher = Cipher.getInstance("AES");
			this.decryptCipher = Cipher.getInstance("AES");
			this.encryptCipher.init(Cipher.ENCRYPT_MODE, this.symetricKeySpec);
			this.decryptCipher.init(Cipher.DECRYPT_MODE, this.symetricKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}	
	}
	
	@Override
	public void send(InetSocketAddress receiver, Serializable payload) {
		SealedObject sealedPayload = null;
		try {
			sealedPayload = new SealedObject(payload, this.encryptCipher);
			super.send(receiver, sealedPayload);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public Message blockingReceive() {
		Message encodedMessage = super.blockingReceive();
		SealedObject sealedPayload = (SealedObject) encodedMessage.getPayload();
		Serializable payload = null;
		try {
			payload = (Serializable) sealedPayload.getObject(this.decryptCipher);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new Message(payload, encodedMessage.getSender());
	}
	
	@Override
	public Message nonBlockingReceive() {
		Message encodedMessage = super.nonBlockingReceive();
		if (encodedMessage == null)
			return null;
		SealedObject sealedPayload = (SealedObject) encodedMessage.getPayload();
		Serializable payload = null;
		try {
			payload = (Serializable) sealedPayload.getObject(this.decryptCipher);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new Message(payload, encodedMessage.getSender());
	}
}
