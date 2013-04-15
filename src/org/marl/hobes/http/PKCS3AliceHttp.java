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

import java.net.URL;

import org.marl.hobes.HobesException;
import org.marl.hobes.secrets.PKCS3Alice;

/**
 * Adds HTTP transport support to the {@link PKCS3Alice} API.
 *  
 * @author chris
 */
public class PKCS3AliceHttp extends PKCS3Alice {

	protected URL trustedPkcs3URL;
	protected int tcpTimeout;
	protected int httpTimeout;
	
	/**
	 * @param id
	 * @param pTrustedPkcs3Url
	 * @param pTcpTimeout
	 * @param pHttpTimeout
	 * @throws HobesException
	 */
	public PKCS3AliceHttp(String id,
			URL pTrustedPkcs3Url,
			int pTcpTimeout,
			int pHttpTimeout) throws HobesException {
		super(id);
		this.trustedPkcs3URL = pTrustedPkcs3Url;
		this.tcpTimeout = pTcpTimeout;
		this.httpTimeout = pHttpTimeout;
	}

	/**
	 * @param id
	 * @param pTrustedPkcs3Url
	 * @throws HobesException
	 */
	public PKCS3AliceHttp(String id, URL pTrustedPkcs3Url) throws HobesException {
		super(id);
		this.trustedPkcs3URL = pTrustedPkcs3Url;
		this.tcpTimeout = HttpObjectBus.DEFAULT_TCP_TIMEOUT;
		this.httpTimeout = HttpObjectBus.DEFAULT_HTTP_TIMEOUT;
	}
	
	/**
	 * @throws HobesException
	 */
	public void completeDiffieHellmanProtocol() 
					throws HobesException{
		protocolPhaseI();
		byte[] bobPublicValue = (byte[]) HttpObjectBus.postWithSource(getId(), 
				trustedPkcs3URL,
				getPublicValue(),
				this.tcpTimeout,
				this.httpTimeout,
				true);
		protocolPhaseII(bobPublicValue);
	}
	
	/**
	 * @param pData
	 * @param pUseResponseFlag
	 * @return
	 * @throws HobesException
	 */
	public Object post(Object pData, boolean pUseResponseFlag) 
			throws HobesException{
		
			return DesObjectBusHttp.postWithSource(trustedPkcs3URL, 
					getId(),
					pData,
					this.tcpTimeout,
					this.httpTimeout,
					pUseResponseFlag,
					getSecretKey());
	}

}
