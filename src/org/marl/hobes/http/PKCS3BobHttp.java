package org.marl.hobes.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;

import javax.crypto.SealedObject;
import javax.crypto.interfaces.DHPublicKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;
import org.marl.hobes.secrets.DesObjectBus;
import org.marl.hobes.secrets.PKCS3Bob;

public class PKCS3BobHttp extends PKCS3Bob {

	protected PKCS3BobHttp(String id, DHPublicKey alicePublicKey) {
		super(id, alicePublicKey);
	}

	/**
	 * @param pInStream
	 * @param pOutStream
	 * @return
	 * @throws HobesSecurityException
	 * @throws HobesTransportException
	 * @throws HobesDataException
	 */
	public Object processRequest(InputStream pInStream, OutputStream pOutStream) 
			throws HobesSecurityException, HobesTransportException, HobesDataException{
		
		Object response = null;
		try {
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			Object header = ois.readObject();
			
			if (header instanceof String){
				// DH agreement request
				String aliceId = (String) header;
				DHPublicKey alicePublicKey = createPublicKey((byte[]) ois.readObject()); 
				
				PKCS3BobHttp bob = new PKCS3BobHttp(aliceId, alicePublicKey);
				bob.protocolPhaseI(alicePublicKey.getParams());
				ObjectBus.write(pOutStream, alicePublicKey.getEncoded());
				
				bob.protocolPhaseII(alicePublicKey.getEncoded());
				response = bob;
			}
			else {
				// FIXME: echo request should fetch a processor if smart is set
				SealedObject cipheredRequest = (SealedObject) header;
				Object plainRequest = DesObjectBus.decipher(cipheredRequest, getSharedSecret());
				DesObjectBus.write(pOutStream, plainRequest, getSharedSecret());
			}
		} 
		catch (IOException e) {
			throw new HobesDataException(e);
		} 
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		} 
		
		return response;
	}
	
}
