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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.secrets.DesObjectBus;
import org.marl.hobes.secrets.PKCS3Alice;

/**
 * Adds HTTP transport support to the {@link PKCS3Alice} API.
 *  
 * @author chris
 */
public class PKCS3AliceHttp extends PKCS3Alice {

	protected URL bobURL;
	protected int tcpTimeout;
	protected int httpTimeout;
	
	public PKCS3AliceHttp(String id,
			URL pPKCS3EndpointUrl,
			int pTcpTimeout,
			int pHttpTimeout) {
		super(id);
		this.bobURL = pPKCS3EndpointUrl;
		this.tcpTimeout = pTcpTimeout;
		this.httpTimeout = pHttpTimeout;
	}

	/**
	 * @param pInStream
	 * @param pOutputStream
	 * @throws HobesException 
	 */
	public void doDiffieHellmanKeyAgreement(DHParameterSpec pDhParams,
			InputStream pInStream, 
			OutputStream pOutputStream) 
					throws HobesException{
		
		protocolPhaseI(pDhParams);
		byte[] bobPublicKey = (byte[]) HttpObjectBus.postWithSource(getId(), 
				bobURL,
				getPublicKey(),
				this.tcpTimeout,
				this.httpTimeout,
				true);
		protocolPhaseII(bobPublicKey);
	}
	
	/**
	 * @param pData
	 * @param pUseResponseFlag
	 * @return
	 * @throws HobesTransportException
	 * @throws HobesSecurityException
	 * @throws HobesDataException
	 */
	public Object post(Object pData, boolean pUseResponseFlag) 
			throws HobesTransportException, HobesSecurityException, HobesDataException{
		
		try {
			HttpURLConnection connection = (HttpURLConnection) bobURL.openConnection();
			connection.setConnectTimeout(this.tcpTimeout);
			connection.setReadTimeout(this.httpTimeout);
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setDoInput(pUseResponseFlag);
			connection.connect();
			
			DesObjectBus.writeWithSource(getId(),
					connection.getOutputStream(),
					pData,
					getSharedSecret()) ;
			if (pUseResponseFlag) {
				return DesObjectBus.read(connection.getInputStream(),
						getSharedSecret());
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
