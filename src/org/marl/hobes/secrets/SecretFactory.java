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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;

/**
 * Manage DES keys and Diffie-Hellman key agreement protocol parameters.
 * <p>Keys and paramaters can be generated, and stored and loaded to/from files,
 * written and red to/from streams.
 * 
 * @author chris
 */
public class SecretFactory {
	private SecretFactory() {}
	
	/** 
	 * Generate a new Diffie-Hellman parameters specification.
	 * 
	 * @return The created specification.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static DHParameterSpec createDhSpec() throws HobesSecurityException {
		// Some central authority creates new DH parameters [IBM comment]
		try {
			 AlgorithmParameterGenerator paramGen = 
					 AlgorithmParameterGenerator.getInstance(KEY_AGREEMENT_ALGORITHM);
			 paramGen.init(512);
			 AlgorithmParameters params = paramGen.generateParameters();
			 return (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
		}
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidParameterSpecException e) {
			throw new HobesSecurityException(e);
		}
	}

	/**
	 * Writes a Diffie-Hellman parameters specification to a stream.
	 * 
	 * @param pOutStream The stream to serialize the specification to.
	 * @param pDhspec The specification.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static void writeDhSpec(OutputStream pOutStream, DHParameterSpec pDhspec) 
			throws HobesTransportException{
		ObjectBus.write(pOutStream, new SerializableDhSpec(pDhspec), SerializableDhSpec.class);
	}
	
	/** 
	 * Creates a Diffie-Hellman parameters specification from a file.
	 * 
	 * @param pPath A path to a file created by the {@link #createDhFile} API.
	 *  
	 * @return The Diffie-Hellman parameters specification.
	 * 
	 * @throws HobesDataException When a marshaling error occurs. 
	 * @throws HobesTransportException  When an I/O error occurs.
	 */
	public static DHParameterSpec createDhSpec(String pPath) 
			throws HobesTransportException, HobesDataException {
		SerializableDhSpec sdh = (SerializableDhSpec) ObjectBus.read(pPath); 
		return sdh.asStandardSpec(); 
	}

	/** 
	 * Generates a Diffie-Hellman parameters specification and serialize
	 * it to a file.
	 * <p>We use the <code>dh</code> extension, but any file name is valid.
	 * 
	 * @param pPath The serialization file path.
	 * 
	 * @return The generated specification.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static DHParameterSpec createDhSpecFile(String pPath) throws HobesSecurityException, HobesTransportException {
		DHParameterSpec dhspec = createDhSpec();
		ObjectBus.write(pPath, new SerializableDhSpec(dhspec), SerializableDhSpec.class);
		return dhspec;
	}

	/** 
	 * Reads a Diffie-Hellman parameters specification from a stream.
	 * 
	 * @param pInStream The stream to read the serialized encoded key from.
	 * Typically a stream built upon a file created by the {@link #createDiffieHellmanFile} API,
	 * or a stream piped to the output of a {@link #writeDiffieHellmanSpec} call.
	 * 
	 * @return The corresponding specifcation.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static DHParameterSpec readDhSpec(InputStream pInStream) 
			throws HobesSecurityException, HobesTransportException, HobesDataException {
		SerializableDhSpec sdhspec = (SerializableDhSpec) ObjectBus.read(pInStream);
		return sdhspec.asStandardSpec();  
	}
	
	/** Generate a DES symmetric key.
	 * 
	 * @return The new secret.
	 * 
	 * @throws HobesSecurityException When the DES algorithm is unavailable.
	 */
	public static SecretKey createSecret() throws HobesSecurityException {
		try{
			return KeyGenerator.getInstance(ENCRYPTION_ALGORITHM).generateKey();
		}	
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
	}
	
	/**
	 * Writes a DES symmetric key to a stream.
	 * 
	 * @param pOutStream The stream to serialize the byte-encoded form of the key.
	 * @param pSecret The secret.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static void writeSecret(OutputStream pOutStream, SecretKey pSecret) 
			throws HobesTransportException, HobesSecurityException{
		ObjectBus.write(pOutStream, pSecret.getEncoded(), byte[].class);
	}
	
	/** 
	 * Generates a DES symmetric key, and store to a file.
	 * <p>We use the <code>des</code> file extension, but any file name is valid.
	 * 
	 * @param pPath A file path to serialize the byte-encoded form of the key.
	 * 
	 * @return The new secret.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs. 
	 * @throws HobesTransportException  When an I/O error occurs.
	 */
	public static SecretKey createSecretFile(String pPath) 
			throws HobesSecurityException, HobesTransportException {
		
		try{
			SecretKey secret = createSecret(); 
			FileOutputStream fos = new FileOutputStream(pPath);
			writeSecret(fos, secret);
			fos.close();
			return secret;
		}	
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		} 
	}

	/** 
	 * Creates a DES symmetric key from a byte-encoded form.
	 * 
	 * @param bytes The byte-encoded key.
	 * 
	 * @return The corresponding secret.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static SecretKey createKey(byte[] bytes) throws HobesSecurityException {
		
		try {
			return SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM)
					.generateSecret(new DESKeySpec(bytes));
		}
		catch (InvalidKeySpecException e) {
			throw new HobesSecurityException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		}
	}

	/** 
	 * Create a DES symmetric key from file.
	 * 
	 * @param pPath A path to a file containing a serialized byte-encoded key,
	 * typically created by the {@link #createSecretFile} API.
	 * 
	 * @return The corresponding secret.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs. 
	 */
	public static SecretKey createSecret(String pPath) 
			throws HobesTransportException, HobesSecurityException, HobesDataException {
		
		try {
			FileInputStream fis = new FileInputStream(pPath);
			SecretKey secret = readSecret(fis);
			fis.close();
			return secret;
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}

	/** 
	 * Creates a DES symmetric key from a stream.
	 * 
	 * @param pInStream The stream to read the byte-encoded key from.
	 * 
	 * @return The created secret.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException 
	 */
	public static SecretKey readSecret(InputStream pInStream) 
			throws HobesSecurityException, HobesTransportException, HobesDataException{
		
		return createKey((byte[]) ObjectBus.read(pInStream));
	}

	
	/** Diffie-Hellman key agreement algorithm.
	 */
	public static final String KEY_AGREEMENT_ALGORITHM = "DH";
	
	/** DES (56 bits) encryption.
	 */
	public static final String ENCRYPTION_ALGORITHM = "DES";

}
