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


import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;

/** Tools to generate and store DES symmetric keys and Diffie-Hellman parameters.
 * 
 * @author chris
 */
public class SecretManager {

	/** Default DES secret.
	 * 
	 * @return
	 * @throws HobesException
	 */
	public static SecretKey getDefaultSecret() throws HobesException{
		return SecretFactory.readSecret(
				SecretManager.class.getClassLoader()
				.getResourceAsStream("org/marl/hobes/secrets/default.des")
				);
	}
	
	/** Default DH parameters.
	 * 
	 * @return
	 * @throws HobesException
	 */
	public static DHParameterSpec getDefaultDhParams() throws HobesException{
		return SecretFactory.readDhParams(
				SecretManager.class.getClassLoader().
				getResourceAsStream("org/marl/hobes/secrets/default.dh")
				);
	}
	
	/**
	 * Answers the Diffie-Hellman public value (PV) that is trusted on this site.
	 * <p>The X509 encoded form of this key is deserialized from the resource
	 * <code>org/marl/hobes/secrets/bob.PV</code>. This resource should be available
	 * at both ends of the channel.
	 * 
	 * @return The public key to use to initialize a Diffie-Hellman protocol.
	 * @throws HobesDataException 
	 * @throws HobesTransportException 
	 * @throws HobesSecurityException 
	 */
	public static DHPublicKey getTrustedPublicValue() 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		
		InputStream is = 
				SecretFactory.class.getClassLoader().getResourceAsStream("org/marl/hobes/secrets/bob.PV");
		byte[] encodedKey = (byte[]) ObjectBus.read(is);
		try{
			is.close();
		}
		catch(IOException e){
			throw new HobesSecurityException(e);
		}
		return SecretFactory.createPublicKey(encodedKey);
	}
	
	/**
	 * @param pEncodedPV
	 * @return
	 * @throws HobesTransportException
	 * @throws HobesDataException
	 * @throws HobesSecurityException
	 */
	public static boolean isTrustedPublicValue(byte[] pEncodedPV)
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		return Arrays.equals(getTrustedPublicValue().getEncoded(), pEncodedPV);
	}
	
	/**
	 * Answers the Diffie-Hellman private value (PV) that is trusted on this site.
	 * <p>The PKCS8 encoded form of this key is deserialized from the resource
	 * <code>org/marl/hobes/secrets/bob.x</code>. This resource should be available
	 * only at Bob side of the channel.
	 * 
	 * @return The private key to use to initialize a Diffie-Hellman protocol.
	 * 
	 * @throws HobesDataException 
	 * @throws HobesTransportException 
	 * @throws HobesSecurityException 
	 */
	public static DHPrivateKey getTrustedPrivateValue() 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		
		InputStream is = 
				SecretFactory.class.getClassLoader().getResourceAsStream("org/marl/hobes/secrets/bob.x");
		byte[] encodedKey = (byte[]) ObjectBus.read(is);
		try{
			is.close();
		}
		catch(IOException e){
			throw new HobesSecurityException(e);
		}
		return SecretFactory.createPrivateKey(encodedKey);
	}
}
