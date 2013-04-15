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

import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.SourcedObject;

/**
 * Represents a DES encrypted commuication channel.
 * It's a symmetric channel.
 * 
 * @author chris
 *
 */
public class DesChannel {

	protected String id;
	protected SecretKey sharedSecret = null;
	
	/** 
	 * Initialize a new DES channel.
	 *   
	 * @param id An identifier to refere to this channel.
	 * @param sharedSecret The symmetric key to use on this channel
	 */
	public DesChannel(String id, SecretKey sharedSecret) {
		super();
		this.id = id;
		this.sharedSecret = sharedSecret;
	}

	/** Answers this DES channel identifier.
	 * 
	 * @return An identifier to refer to this DES channel.
	 */
	public String getId() {
		return id;
	}
	
	/**
	 * Answers the symmetric key used through this channel.
	 * 
	 * @return The shared secret used on this channel.
	 * @throws HobesSecurityException When the secret has not been set.
	 */
	public SecretKey getSecretKey() throws HobesSecurityException{
		if (this.sharedSecret == null){
			throw new HobesSecurityException();
		}
		return this.sharedSecret;
	}

	
	/** 
	 * Serializes  an object to a stream, using this channel DES
	 * configuration.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 */
	public void write(OutputStream pOutStream, Object pData) 
			throws HobesTransportException, HobesSecurityException{
		DesObjectBus.write(pOutStream, pData, getSecretKey());
	}

	/** 
	 * Serializes an object to a stream, along with the information
	 * identifying its source, using this channel DES configuration.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 * @throws HobesSecurityException When a cryptography error.
	 */
	public void writeWithSource(String pSourceId, OutputStream pOutStream, Object pData)
			throws HobesTransportException, HobesSecurityException{
		DesObjectBus.writeWithSource(pSourceId, pOutStream, pData, getSecretKey());
	}
	
	/** 
	 * Deserializes an object from a stream, using this channel DES
	 * configuration.
	 * <p>The payload is the plain object deciphered using the channel key.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The deserialized object. Its type should correspond to the serialization type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 * @throws HobesSecurityException  When a cryptography error occurs.
	 */
	public Object read(InputStream pInStream) 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		return DesObjectBus.read(pInStream, getSecretKey());
	}

	/** 
	 * Deserializes an object from a stream, along with the information
	 * identifying its source, using this channel DES configuration
	 * <p>The payload is the plain object deciphered using the channel key.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The source identifier and the deserialized <b>sealed</b> object as payload.
	 * 
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public SourcedObject readWithSource(InputStream pInStream) 
			throws HobesTransportException, HobesDataException, HobesSecurityException{
		return DesObjectBus.readWithSource(pInStream, getSecretKey());
	}
	
	public Object decipher(Object pData) throws HobesSecurityException, HobesTransportException, HobesDataException {
		return DesObjectBus.decipher((SealedObject) pData,getSecretKey());
	}
			
	public SealedObject cipher(Object pData) throws HobesSecurityException, HobesTransportException{
		return DesObjectBus.cipher(pData, getSecretKey());
	}

}
