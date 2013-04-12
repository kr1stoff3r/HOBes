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
package org.marl.hobes.http;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.crypto.SecretKey;

import org.marl.hobes.HobesException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.secrets.DesObjectBus;

/** 
 * Provides an API similar to {@link org.marl.hobes.secret.DesObjectBus}, but adapted to HTP transport.
 * 
 * @author chris
 */
public class HttpDesObjectBus {
	
	/** 
	 * Serializes an object as the payload of an HTTP <code>POST</code> request.
	 * <p>The object is ciphered with the provided key before serialization. 
	 * <p> When the <code>pUseResponseFlag</code> parameter is set,
	 * the function also deserializes an object from the response content,
	 * using the same key for deciphering.
	 * 
	 * @param pUrl The location of an agent that conforms to the
	 * {@link org.marl.hobes.DesObjectBus#read} and
	 * {@link org.marl.hobes.DesObjectBus#write} API.
	 * @param pData A serializable object.
	 * @param pTcpTimeout The TCP connection timeout.
	 * @param pHttpTimeout The HTTP read timeout.
	 * @param pUseResponseFlag Determines whether an object will be deserialized
	 * from the HTTP response content.
	 * 
	 * @return The deserialized object, or <code>null</code> if the
	 * <code>pUseResponseFlag</code> is not set.
	 * 
	 * @throws HobesException When an error occurs.
	 */
	public static Object post(URL pUrl,
			Object pData, 
			int pTcpTimeout,
			int pHttpTimeout,
			boolean pUseResponseFlag,
			SecretKey pSharedKey) throws HobesException {
		
		try {
			HttpURLConnection connection = (HttpURLConnection) pUrl.openConnection();
			connection.setConnectTimeout(pTcpTimeout);
			connection.setReadTimeout(pHttpTimeout);
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setDoInput(pUseResponseFlag);
			connection.connect();
			
			DesObjectBus.write(connection.getOutputStream(), pData, pSharedKey) ;
			if (pUseResponseFlag) {
				return DesObjectBus.read(connection.getInputStream(), pSharedKey);
			}
			else {
				return null;
			}
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
}
