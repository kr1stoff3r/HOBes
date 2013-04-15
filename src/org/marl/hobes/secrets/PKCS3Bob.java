package org.marl.hobes.secrets;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;

public class PKCS3Bob extends PKCS3Actor {

	protected DHPrivateKey privateValue;
	
	/**
	 * @param id
	 * @param alicePublicKey
	 * @throws HobesSecurityException 
	 * @throws HobesDataException 
	 * @throws HobesTransportException 
	 */
	public PKCS3Bob(String id) 
			throws HobesTransportException, HobesDataException, HobesSecurityException {
		super(id);
		this.publicValue = SecretManager.getTrustedPublicValue();
		this.privateValue = SecretManager.getTrustedPrivateValue();
	}
	
	/**
	 * @param pPublicKey
	 * @param pPrivateKey
	 * @throws HobesException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public void protocolPhaseI()
			throws HobesException{
		try{
			this.dhProtocolAgreement = KeyAgreement.getInstance(SecretFactory.KEY_AGREEMENT_ALGORITHM);
			this.dhProtocolAgreement.init(this.privateValue);
			
			this.state = STATE_PHASE_I;
		} 
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		} 
	}

}
