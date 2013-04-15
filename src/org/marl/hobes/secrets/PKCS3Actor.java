/*
This file is part of HOBes.

HOBes is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

HOBes is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with HOBes.  If not, see <http://www.gnu.org/licenses/>.
 
*/
package org.marl.hobes.secrets;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;


/**
 * Represents a participant in a PKCS3 Diffie-Hellman key agreement protocol.
 * <p>This participant implement the two phases of the protocol, as described
 * in <a href="pkcs-3.txt">PKCS #3: Diffie-Hellman Key-Agreement Standard</a>:
 * <ul>
 * <li>{@link #protocolPhaseI(DHParameterSpec)}</li>
 * <li>{@link #protocolPhaseII(byte[])}</li>
 * </ul>
 * 
 * @see PKCS3Bob Bob
 * @see PKCS3Alice Alice
 * 
 * @author chris
 */
public class PKCS3Actor extends DesChannel {

	/** The agent has just been initialized with
	 * an identifier for the corresponding DES channel. */
	public static final int STATE_NEW =0;
	
	/** The agent has generated private and public keys,
	 * based on some Diffie-Hellman parameters.
	 */
	public static final int STATE_PHASE_I = 1; 
	
	/** The agent has computed the symmetric key, the secret,
	 * based on peer public key.
	 */
	public static final int STATE_PHASE_II = 2; 
	
	// the agent conversational state
	protected int state = STATE_NEW;
	
	// the symmetric key
	protected SecretKey secretKey = null;
	
	// the agent public and private keys
	protected DHPublicKey publicValue = null;
	
	// the DH key agreement protocol implementation
	protected KeyAgreement dhProtocolAgreement = null;
	
	
	/** 
	 * Creates a PKCS3 agent, in conversational state <code>STATE_NEW</code>.
	 * 
	 * @param id An identifier to refer to the corresponding DES channel.
	 */
	public PKCS3Actor(String id) {
		super(id, null);
	}
	
	/** 
	 * Answsers the conversational state of this agent
	 * regarding the Diffie-Hellman key agreement protocol.
	 * 
	 * @return One of {@link #STATE_NEW}, {@link #STATE_PHASE_I}, {@link #STATE_PHASE_II}. 
	 */
	public int getState() {
		return state;
	}

	/**
	 * Answers the agreed shared secret resulting from the
	 * Diffie-Hellman key agreement protocol.
	 * 
	 * @return The symmetric key of the corresponding DES channel.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public SecretKey getSecretKey() throws HobesSecurityException {
		if (getState() < STATE_PHASE_II){
			throw new HobesSecurityException(new IllegalStateException(String.valueOf(getState())));
		}
		return this.secretKey;
	}

	/**
	 * Answers this agent public key. 
	 * 
	 * @return The public key X509 byte-encoded form.
	 * 
	 * @throws HobesSecurityException When this agent has not completed
	 * Diffie-Hellman protocol phase I.
	 */
	public byte[] getPublicValue() throws HobesSecurityException {
		if (getState() < STATE_PHASE_I){
			throw new HobesSecurityException (new IllegalStateException(String.valueOf(getState())));
		}
		return publicValue.getEncoded();
	}

	
	/** 
	 * Proceeds to the first phase of Diffie-Hellman key agreement.
	 * <p>In this phase the agent generates its private and public key pair,
	 * based on the provided Diffie-Hellman parameters.
	 * <p> At the end of this phase, the agent should find itself
	 *  in state <code>STATE_PHASE_I</code>.
	 * 
	 * @param dhspec The input Diffie-Hellman parameters.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public void protocolPhaseI(DHParameterSpec dhspec) throws HobesSecurityException{
		try{
			KeyPairGenerator kpairGen = 
					KeyPairGenerator.getInstance(SecretFactory.KEY_AGREEMENT_ALGORITHM);
			kpairGen.initialize(dhspec);
			KeyPair keyPair = kpairGen.generateKeyPair();
			
			this.publicValue = (DHPublicKey) keyPair.getPublic();
			this.dhProtocolAgreement = KeyAgreement.getInstance(SecretFactory.KEY_AGREEMENT_ALGORITHM); 
			this.dhProtocolAgreement.init(keyPair.getPrivate());
			
			this.state = STATE_PHASE_I;
		}
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		} 
		catch (InvalidAlgorithmParameterException e) {
			throw new HobesSecurityException(e);
		} 
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		}
	}
	
	/**
	 * Proceeds to the second phase of Diffie-Hellman key agreement.
	 * <p>During this phase an agent independently computes the
	 * agreed secret key resulting from Diffie-Hellman parameters
	 * and peer public key.
	 * <p> At the end of this phase, the agent should find itself
	 *  in state <code>STATE_PHASE_II</code>, and be able to read and write
	 *  on the established DES channel.
	 * 
	 * @param peerEncodedPV The peer byte-encoded public key.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public void protocolPhaseII(byte[] peerEncodedPV) 
			throws HobesException{
		
		if (getState() != STATE_PHASE_I){
			throw new HobesSecurityException(new IllegalStateException(String.valueOf(getState())));
		}
		
		try{
			this.dhProtocolAgreement.doPhase(SecretFactory.createPublicKey(peerEncodedPV), true);
			
			this.secretKey = 
					this.dhProtocolAgreement.generateSecret(SecretFactory.ENCRYPTION_ALGORITHM);
			
			this.state = STATE_PHASE_II;
		} 
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		} 
		catch (IllegalStateException e) {
			throw new HobesSecurityException(e);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
	}
}
