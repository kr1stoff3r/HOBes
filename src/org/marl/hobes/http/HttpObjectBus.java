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

import org.marl.hobes.HobesException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;

/** 
 * Provides an API similar to {@link org.marl.hobes.ObjectBus}, but adapted to HTP transport.
 * <p>It also provides a few HTTP connections related helpers.
 * 
 * @author chris
 */
public class HttpObjectBus {

	/** MIME type used for hobes HTTP serialization. */
	public static final String HOBES_CONTENT_TYPE = "application/x-java-serialized-object";
	
	/** Default connection timeout, 3 seconds. */
	public static final int DEFAULT_TCP_TIMEOUT = 1000 * 3;
	/** Default HTTP read timeout, 3 seconds. */
	public static final int DEFAULT_HTTP_TIMEOUT = 1000 * 3;
	/** Debug connection timeout, infinite. */
	public static final int DEBUG_TCP_TIMEOUT = 0;
	/** Debug HTTP read timeout, infinite. */
	public static final int DEBUG_HTTP_TIMEOUT = 0;
	
	/** 
	 * Open an bidirectional HTTP connection using specified timeouts.
	 * 
	 * @param pUrl The URL to connect to.
	 * @param pTcpTimeout The TCP connection timeout to use.
	 * @param pHttpTimeout the HTTP read timeout to use.
	 * 
	 * @return An open HTTP connection.
	 * 
	 * @throws HobesTransportException When an error occurs.
	 */
	public static HttpURLConnection openConnection(URL pUrl, int pTcpTimeout, int pHttpTimeout) 
			throws HobesTransportException {
		try{
			HttpURLConnection connection = (HttpURLConnection) pUrl.openConnection();
			connection.setConnectTimeout(pTcpTimeout);
			connection.setReadTimeout(pHttpTimeout);
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.connect();
			return connection;
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}
	
	/** 
	 * Open a bidirectional HTTP connection using default timeouts.
	 * 
	 * @param pUrl The URL to connect to.
	 * 
	 * @return An open HTTP connection.
	 * 
	 * @throws HobesTransportException When an error occurs.
	 */
	public static HttpURLConnection openConnection(URL pUrl) throws HobesTransportException {
		return openConnection(pUrl, DEFAULT_TCP_TIMEOUT, DEFAULT_HTTP_TIMEOUT);
	}
	
	/** 
	 * Open a bidirectional HTTP connection using debug timeouts.
	 * 
	 * @param pUrl The URL to connect to.
	 * 
	 * @return An open HTTP connection.
	 * 
	 * @throws HobesTransportException When an error occurs.
	 */
	public static HttpURLConnection openDebugConnection(URL pUrl) throws HobesTransportException {
		return openConnection(pUrl, DEBUG_TCP_TIMEOUT, DEBUG_HTTP_TIMEOUT);
	}

	/** 
	 * Serializes an object as the payload of an HTTP <code>POST</code> request.
	 * <p> When the <code>pUseResponseFlag</code> parameter is set,
	 * the function also deserializes an object from the response content.
	 * 
	 * @param pUrl The location of an agent that conforms to the
	 * {@link org.marl.hobes.ObjectBus#read} and
	 * {@link org.marl.hobes.ObjectBus#write} API.
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
			boolean pUseResponseFlag) throws HobesException {
		
		try {
			HttpURLConnection connection = (HttpURLConnection) pUrl.openConnection();
			connection.setConnectTimeout(pTcpTimeout);
			connection.setReadTimeout(pHttpTimeout);
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setDoInput(pUseResponseFlag);
			connection.connect();
			
			ObjectBus.write(connection.getOutputStream(), pData) ;
			if (pUseResponseFlag) {
				return ObjectBus.read(connection.getInputStream());
			}
			else {
				return null;
			}
		}
		catch (IOException e) {
			throw new HobesTransportException(e);
		}
	}

	/**
	 * @param pSourceId
	 * @param pUrl
	 * @param pData
	 * @param pTcpTimeout
	 * @param pHttpTimeout
	 * @param pUseResponseFlag
	 * @return
	 * @throws HobesException
	 */
	public static Object postWithSource(String pSourceId,
			URL pUrl,
			Object pData, 
			int pTcpTimeout,
			int pHttpTimeout,
			boolean pUseResponseFlag) throws HobesException {

		try {
			HttpURLConnection connection = (HttpURLConnection) pUrl.openConnection();
			connection.setConnectTimeout(pTcpTimeout);
			connection.setReadTimeout(pHttpTimeout);
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setDoInput(pUseResponseFlag);
			connection.connect();
			
			ObjectBus.writeWithSource(pSourceId, connection.getOutputStream(), pData) ;
			if (pUseResponseFlag) {
				return ObjectBus.read(connection.getInputStream());
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
