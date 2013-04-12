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
package org.marl.hobes;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

/** 
 * Implements function calls to read and write Java objects, easily and consistently,
 *  to/from streams and files.
 * 
 * @author chris
 */
public abstract class ObjectBus {
	private ObjectBus() {}

	/** 
	 * Serializes an object to a stream.
	 * 
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * @param pType The serialization type, which can differ from the runtime type.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 */
	public static void write(OutputStream pOutStream, 
			Serializable pData,
			Class<? extends Serializable> pType) throws HobesTransportException {
		
		try {
			ObjectOutputStream oos = new ObjectOutputStream(pOutStream);
			oos.writeObject(pType.cast(pData));
			oos.close();
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/** 
	 * Serializes an object to a file.
	 *  
	 * @param pPath The destination file path.
	 * @param pData A serializable object.
	 * @param pType The serialization type, which can differ from the runtime type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static void write(String pPath, 
			Serializable pData,
			Class<? extends Serializable> pType) throws HobesTransportException {
	
		try {
			FileOutputStream fos = new FileOutputStream(pPath);
			write(fos, pData, pType);
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
	 * Serializes an object to a stream, along with the information
	 * identifying its source.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * @param pType The serialization type, which can differ from the runtime type.
	 * 
	 * @throws HobesTransportException When the stream is corrupted.
	 */
	public static void writeWithSource(String pSourceId,
			OutputStream pOutStream, 
			Serializable pData,
			Class<? extends Serializable> pType) throws HobesTransportException {
		try {
			ObjectOutputStream oos = new ObjectOutputStream(pOutStream);
			oos.writeObject(pSourceId);
			oos.writeObject(pType.cast(pData));
			oos.close();
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/**
	 * Serializes an object to a file, along with the information
	 * identifying its source.
	 * 
	 * @param pSourceId The source identifier.
	 * @param pPath The destination file path.
	 * @param pOutStream An open stream to write to. This stream should not be re-open.
	 * @param pData A serializable object.
	 * @param pType The serialization type, which can differ from the runtime type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public static void writeWithSource(String pSourceId,
			String pPath,
			Serializable pData,
			Class<? extends Serializable> pType) throws HobesTransportException {
		try {
			FileOutputStream fos = new FileOutputStream(pPath);
			writeWithSource(pSourceId, fos, pData, pType);
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
	 * Deserializes an object from a stream.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The deserialized object. Its type should correspond to the serialization type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static Object read(InputStream pInStream)
			throws HobesTransportException, HobesDataException {
		
		try {
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			Object obj = ois.readObject();
			ois.close();
			return obj;
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		}
	}

	/** 
	 * Deserializes an object from a file.
	 * 
	 * @param pPath Path to a file created using the {@link write} API.
	 * @param pType The deserialization type, that should correspond to the serialization type.
	 * 
	 * @return The deserialized object. Its type should correspond to the serialization type.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static Object read(String pPath) 
			throws HobesTransportException, HobesDataException {
		
		try {
			FileInputStream fis = new FileInputStream(pPath);
			Object obj = read(fis);
			fis.close();
			return obj;
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		} catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/** 
	 * Deserializes an object from a stream, along with the information
	 * identifying its source.
	 * 
	 * @param pInStream An open stream to read from. This stream should not be re-open.
	 * 
	 * @return The source identifier and the deserialized object as payload.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static SourcedObject readWithSource(InputStream pInStream)
			throws HobesTransportException, HobesDataException {
		try {
			ObjectInputStream ois = new ObjectInputStream(pInStream);
			String sourceId = (String) ois.readObject();
			Object payload = ois.readObject();
			ois.close();
			return new SourcedObject(sourceId, payload);
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(e);
		}
	}
	
	/** 
	 * Deserializes an object from a file, along with the information
	 * identifying its source.
	 * 
	 * @param pPath Path to a file created using the {@link write} API.
	 * 
	 * @return The source identifier and the deserialized object as payload.
	 * 
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public static SourcedObject readWithSource(String pPath)
			throws HobesTransportException, HobesDataException {
		
		try {
			FileInputStream fis = new FileInputStream(pPath);
			SourcedObject obj = readWithSource(fis);
			fis.close();
			return obj;
		}
		catch (FileNotFoundException e) {
			throw new HobesTransportException(pPath, e);
		} catch (IOException e) {
			throw new HobesTransportException(e);
		}
		
	}
	
	/** Testing helper, converts bytes to a hexadecimal string representation.
	 * <p>See
	 * <a href="http://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l/2197650#2197650">
	 * In Java, how do I convert a byte array to a string of hex digits while keeping leading zeros?</a> for a simple discussion.
	 * </p>
	 * 
	 * @param bytes The bytes.
	 * @return The hexadecimal string representation.
	 */
	public static String bytestoHex(byte[] bytes){
		// cf. http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
		final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);		
	}
}
