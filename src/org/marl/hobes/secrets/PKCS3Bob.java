package org.marl.hobes.secrets;

import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.interfaces.DHPublicKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;

public class PKCS3Bob extends PKCS3Actor {

	/**
	 * @param id
	 * @param alicePublicKey
	 */
	protected PKCS3Bob(String id, DHPublicKey alicePublicKey) {
		super(id);
		this.peerEncodedPublicKey = alicePublicKey.getEncoded();
	}
	
	/** 
	 * Initiates a Diffie-Hellman key agreement protocol, based on Alice
	 * public key and DH parameters.
	 * 
	 * <p>Bob does its phase I of the protocol.
	 * 
	 * @param pInStream The stream to deserialize Alice byte-encoded public key from.
	 * 
	 * @return The corresponding Bob actor, in state <code>STATE_PHASE_I</code>.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static PKCS3Bob initiateDhAgreementProtocol(InputStream pInStream) 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		
		SourcedObject dhHandshake = ObjectBus.readWithSource(pInStream);
		
		DHPublicKey alicePublicKey = createPublicKey((byte[]) dhHandshake.getPayload()); 
		
		PKCS3Bob bob = new PKCS3Bob(dhHandshake.getSource(), alicePublicKey);
		bob.protocolPhaseI(alicePublicKey.getParams());
		
		return bob;
	}

	/**
	 * Bob completes the Diffie-Hellman key agreement protocol by
	 * sending its public key to Alice, and proceeding to
	 * phase II of the Diffie-Hellman protocol.
	 * <p>After this phase, this actor should find itself in state 
	 * <code>STATE_PHASE_II</code> and be able to communicate over
	 * the established DES channel.
	 * 
	 * @param pOutStream The stream to serialize this actor public key to.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException 
	 */
	public void completeDhAgreementProtocol(OutputStream pOutStream) 
			throws HobesTransportException, HobesSecurityException{
		ObjectBus.write(pOutStream, getPublicKey());
		
		protocolPhaseII(this.peerEncodedPublicKey);
	}
	
}
