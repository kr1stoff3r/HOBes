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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;

/**
 * Adds DES encryption support to the {@link org.marl.hobes.ObjectBus} API.
 * 
 * @author chris
 *
 */
public abstract class DesObjectBus {
	private DesObjectBus() {}
	
	/** 
	 * Ciphers an object using DES-encryption.
	 * 
	 * @param pData A serializable object.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @return A sealed object containing the ciphered data.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static SealedObject cipher(Object pData,	SecretKey pSharedSecret)
			throws HobesSecurityException, HobesTransportException{
		
		try {
			Cipher cipher = Cipher.getInstance(SecretFactory.ENCRYPTION_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, pSharedSecret);
			return new SealedObject((Serializable) pData, cipher);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		} 
		catch (NoSuchPaddingException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		} 
		catch (IllegalBlockSizeException e) {
			throw new HobesSecurityException(e);
		} 
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/**
	 * Deciphers a DES encrypted object.
	 * 
	 * @param sealedObject A sealed object containing the ciphered data.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @return The deciphered data.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static Object decipher(SealedObject sealedObject, SecretKey pSharedSecret) 
			throws HobesSecurityException, HobesTransportException, HobesDataException {
		
		try {
			Cipher cipher = Cipher.getInstance(SecretFactory.ENCRYPTION_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, pSharedSecret);
			return sealedObject.getObject(cipher);
		}
		catch (NoSuchAlgorithmException e) {
			throw new HobesSecurityException(e);
		}
		catch (NoSuchPaddingException e) {
			throw new HobesSecurityException(e);
		}
		catch (InvalidKeyException e) {
			throw new HobesSecurityException(e);
		} 
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		} 
		catch (IllegalBlockSizeException e) {
			throw new HobesSecurityException(e);
		}
		catch (BadPaddingException e) {
			throw new HobesSecurityException(e);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}

	/** 
	 * Serializes  an object to a DES-encrypted stream.
	 * 
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static void write(OutputStream pOutStream, 
			Object pData,
			SecretKey pSharedSecret)
					throws HobesTransportException, HobesSecurityException {
		
			ObjectBus.write(pOutStream, cipher(pData, pSharedSecret));
	}

	/** 
	 * Serializes an object to a DES-encrypted file.
	 * 
	 * @param pPath The serialization file path.
	 * @param pData A serializable object.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static void write(String pPath,
			Object pData,
			SecretKey pSharedSecret)
					throws HobesTransportException, HobesSecurityException {
		
		try{
			FileOutputStream fos = new FileOutputStream(pPath);
			write(fos, pData, pSharedSecret);
			fos.close();
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}

	/** 
	 * Serializes an object to a DES encrypted stream, along with the information
	 * identifying its source.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 * @throws HobesSecurityException When a cryptography error.
	 */
	public static void writeWithSource(String pSourceId,
			OutputStream pOutStream, 
			Object pData,
			SecretKey pSharedSecret) throws HobesTransportException, HobesSecurityException {
		
		try{
			ObjectOutputStream oos = new ObjectOutputStream(pOutStream);
			oos.writeObject(pSourceId);
			oos.writeObject(cipher(pData, pSharedSecret));
			oos.close();
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}		
	}
	
	/** 
	 * Serializes an object to a DES encrypted file, along with the information
	 * identifying its source.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pPath The serialization file path.
	 * @param pData A serializable object.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 * @throws HobesSecurityException When a cryptography error.
	 */
	public static void writeWithSource(String pSourceId,
			String pPath, 
			Object pData,
			SecretKey pSharedSecret) 
					throws HobesTransportException, HobesSecurityException {
		
		try {
			FileOutputStream fos = new FileOutputStream(pPath);
			writeWithSource(pSourceId, fos, pData, pSharedSecret);
			fos.close();
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	
	/** 
	 * Deserializes an object from a DES encrypted stream.
	 * <p>The payload is the plain object deciphered using the provided key.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The deserialized object. Its type should correspond to the serialization type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException  When a cryptography error occurs.
	 */
	public static Object read(InputStream pInStream,
			SecretKey pSharedSecret)
			throws HobesTransportException, HobesDataException, HobesSecurityException {

		try {
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			SealedObject sealedObject = (SealedObject) ois.readObject();
			ois.close();
			return decipher(sealedObject, pSharedSecret);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		}
	}

	/** 
	 * Deserializes an object from a DES encrypted file.
	 * <p>The payload is the plain object deciphered using the provided key.
	 * 
	 * @param pPath the source file path.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @return The deserialized object. Its type should correspond to the serialization type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException  When a cryptography error occurs.
	 */
	public static Object read(String pPath,
			SecretKey pSharedSecret)
			throws HobesTransportException, HobesDataException, HobesSecurityException {

		try {
			FileInputStream fis = new FileInputStream(pPath);
			Object obj = read(fis, pSharedSecret);
			fis.close();
			return obj;
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}

	/** 
	 * Deserializes an object from a DES-encrypted stream, along with the information
	 * identifying its source.
	 * <p>The payload should then be deciphered using the appropriate key.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The source identifier and the deserialized <b>sealed</b> object as payload.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static SourcedObject readWithSource(InputStream pInStream)
			throws HobesTransportException, HobesDataException {
		try{
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			String sourceId = (String) ois.readObject();
			SealedObject sealedPayload = (SealedObject) ois.readObject();
			ois.close();
			return new SourcedObject(sourceId, sealedPayload);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		} 
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/** 
	 * Deserializes an object from a DES-encrypted file, along with the information
	 * identifying its source.
	 * <p>The payload should then be deciphered using the appropriate key.
	 * 
	 * @param pPath Path to a file created using the {@link write} API.
	 * 
	 * @return The source identifier and the deserialized <b>sealed</b> object as payload.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesTransportException When a marshaling error occurs.
	 */
	public static SourcedObject readWithSource(String pPath)
			throws HobesTransportException, HobesDataException {
		try{
			FileInputStream fis = new FileInputStream(pPath);
			SourcedObject sourcedObj = readWithSource(fis);
			fis.close();
			return sourcedObj;
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/** 
	 * Deserializes an object from a DES-encrypted stream, along with the information
	 * identifying its source.
	 * <p>The payload is the plain object deciphered using the provided key.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @return The source identifier and the deserialized <b>plain</b> object as payload.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public static SourcedObject readWithSource(InputStream pInStream, SecretKey pSharedSecret)
			throws HobesTransportException, HobesDataException, HobesSecurityException {
		try{
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			String sourceId = (String) ois.readObject();
			SealedObject sealedPayload = (SealedObject) ois.readObject();
			Object obj = decipher(sealedPayload,pSharedSecret);
			ois.close();
			return new SourcedObject(sourceId, obj);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		} 
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}	

	/** 
	 * Deserializes an object from a DES encrypted file, along with the information
	 * identifying its source.
	 * <p>The payload is the plain object deciphered using the provided key.
	 * 
	 * @param pPath Path to a file created using the {@link write} API.
	 * @param pSharedSecret The symmetric key to use.
	 * 
	 * @return The source identifier and the deserialized <b>plain</b> object as payload.
	 * 
	 * @throws HobesTransportException
	 * @throws HobesDataException
	 * @throws HobesSecurityException
	 */
	public static SourcedObject readWithSource(String pPath, SecretKey pSharedSecret)
			throws HobesTransportException, HobesDataException, HobesSecurityException {
		
		try {
			FileInputStream fis = new FileInputStream(pPath);
			SourcedObject obj = readWithSource(fis, pSharedSecret);
			fis.close();
			return obj;
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		} catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
}