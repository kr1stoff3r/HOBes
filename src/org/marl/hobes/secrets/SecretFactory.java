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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;

/**
 * Manage public, private and DES symmetric keys, and Diffie-Hellman protocol parameters. 
 * <p>Keys and paramaters can be generated, and stored and loaded to/from files,
 * written and red to/from streams.
 * 
 * @author chris
 */
public class SecretFactory {
	private SecretFactory() {}
	
	/** 
	 * Generates new Diffie-Hellman parameters.
	 * 
	 * @return The generated DH parameters.
	 * 
	 * @throws HobesSecurityException When the DH algorithm is unavailable.
	 */
	public static DHParameterSpec createDhParams() throws HobesSecurityException {
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
	 * Writes Diffie-Hellman parameters to a stream.
	 * 
	 * @param pOutStream The stream to serialize the parameters to.
	 * @param pDhParams The DH parameters.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static void writeDhParams(OutputStream pOutStream, DHParameterSpec pDhParams) 
			throws HobesTransportException{
		ObjectBus.write(pOutStream, new SerializableDhSpec(pDhParams));
	}
	
	/** 
	 * Generates new Diffie-Hellman parameters and serialize them
	 * to a file.
	 * <p>We use the <code>dh</code> extension, but any file name is valid.
	 * 
	 * @param pPath The serialization file path.
	 * 
	 * @return The generated parameters.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static DHParameterSpec createDhParamsFile(String pPath) throws HobesSecurityException, HobesTransportException {
		DHParameterSpec dhspec = createDhParams();
		ObjectBus.write(pPath, new SerializableDhSpec(dhspec));
		return dhspec;
	}
	
	/** 
	 * Creates a Diffie-Hellman parameters specification from a file.
	 * 
	 * @param pPath A path to a file created by the {@link #createDhParamsFile} API.
	 *  
	 * @return The generated DH parameters.
	 * 
	 * @throws HobesDataException When a marshaling error occurs. 
	 * @throws HobesTransportException  When an I/O error occurs.
	 */
	public static DHParameterSpec createDhParams(String pPath) 
			throws HobesTransportException, HobesDataException {
		SerializableDhSpec sdh = (SerializableDhSpec) ObjectBus.read(pPath); 
		return sdh.asStandardSpec(); 
	}


	/** 
	 * Reads Diffie-Hellman parameters from a stream.
	 * 
	 * @param pInStream The stream to read the serialized parameters from.
	 * Typically a stream built upon a file created by the {@link #createDhParamsFile} API,
	 * or a stream piped to the output of a {@link #writeDhParams} call.
	 * 
	 * @return The retrieved parameters.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static DHParameterSpec readDhParams(InputStream pInStream) 
			throws HobesSecurityException, HobesTransportException, HobesDataException {
		SerializableDhSpec sdhspec = (SerializableDhSpec) ObjectBus.read(pInStream);
		return sdhspec.asStandardSpec();  
	}
	
	/** 
	 * Generate a DES symmetric key.
	 * 
	 * @return The new secret.
	 * 
	 * @throws HobesSecurityException When the DES algorithm is unavailable.
	 */
	public static SecretKey createSecretKey() throws HobesSecurityException {
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
	public static void writeSecretKey(OutputStream pOutStream, SecretKey pSecret) 
			throws HobesTransportException, HobesSecurityException{
		ObjectBus.write(pOutStream, pSecret.getEncoded());
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
	public static SecretKey createSecretKeyFile(String pPath) 
			throws HobesSecurityException, HobesTransportException {
		
		try{
			SecretKey secret = createSecretKey(); 
			FileOutputStream fos = new FileOutputStream(pPath);
			writeSecretKey(fos, secret);
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
	public static SecretKey createSecretKey(byte[] bytes) throws HobesSecurityException {
		
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
	 * typically created by the {@link #createSecretKeyFile} API.
	 * 
	 * @return The corresponding secret.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs. 
	 */
	public static SecretKey createSecretKey(String pPath) 
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
		return createSecretKey((byte[]) ObjectBus.read(pInStream));
	}

	/**
	 * Creates a public key from a (X509) byte-encoded form.
	 * 
	 * @param pEncodedKey The key byte-encoded form.
	 * 
	 * @return The created public key.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static DHPublicKey createPublicKey(byte[] pEncodedKey)
			throws HobesSecurityException{
		try{
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_ALGORITHM);
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pEncodedKey);
			return (DHPublicKey) keyFactory.generatePublic(x509KeySpec);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		} 
		catch (InvalidKeySpecException e) {
			throw new HobesSecurityException(e);
		}
	}

	/**
	 * Creates a private key from a (PKCS8) byte-encoded form.
	 * 
	 * @param pEncodedKey The key byte-encoded form.
	 * 
	 * @return The created public key.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static DHPrivateKey createPrivateKey(byte[] pEncodedKey)
			throws HobesSecurityException{
		try{
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_ALGORITHM);
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pEncodedKey);
			return (DHPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		} 
		catch (InvalidKeySpecException e) {
			throw new HobesSecurityException(e);
		}
	}
	
	/**
	 * Creates a public key from a (X509) byte-encoded form serialized to a file.
	 * 
	 * @param pPath Path to a file to deserialize the encoded key from.
	 * 
	 * @return The created public key.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static DHPublicKey createPublicKey(String pPath) 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		
		byte[] encodedPV = (byte[]) ObjectBus.read(pPath);
		return createPublicKey(encodedPV);
	}
	
	/**
	 * Creates a private key from a (PKCS8) byte-encoded form serialized to a file.
	 * 
	 * @param pPath Path to a file to deserialize the encoded key from.
	 * 
	 * @return The created private key.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static DHPrivateKey createPrivateKey(String pPath) 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		
		byte[] encodedX = (byte[]) ObjectBus.read(pPath);
		return createPrivateKey(encodedX);
	}
	
	/**
	 * Creates files suitable for trusted communication.
	 * <p>The <code>.PV</code> file contains the public key
	 * X509 encoded form, and the <code>.x</code> 
	 * file contains the private key PKCS8 encoded form.
	 * 
	 * @param pDhParams The Diffie-Hellman parameters to use.
	 * @param prefix The generated files will be <code>prefix.PV</code>
	 * and <code>prefix.x</code>.
	 * 
	 * @return The generated public and private keys.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesSecurityException when a cryptography error occurs.
	 */
	public static KeyPair createPVx(DHParameterSpec pDhParams, String prefix) 
			throws HobesTransportException, HobesSecurityException{
		
		try{
			KeyPairGenerator keysFactory = KeyPairGenerator.getInstance(SecretFactory.KEY_AGREEMENT_ALGORITHM);
			keysFactory.initialize(pDhParams);
			KeyPair keys = keysFactory.generateKeyPair();
			
			ObjectBus.write(prefix+".PV", keys.getPublic().getEncoded());
			ObjectBus.write(prefix+".x", keys.getPrivate().getEncoded());
			
			return keys;
		}
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new HobesSecurityException(e);
		} 
	}
	
	/** Diffie-Hellman key agreement algorithm.
	 */
	public static final String KEY_AGREEMENT_ALGORITHM = "DH";
	
	/** DES (56 bits) encryption.
	 */
	public static final String ENCRYPTION_ALGORITHM = "DES";
}
