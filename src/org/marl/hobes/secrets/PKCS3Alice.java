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

import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;

public class PKCS3Alice extends PKCS3Actor {

	/**
	 * Creates an Alice PKCS3 actor.
	 * 
	 * @param id An identifier to refer to the corresponding
	 * DES channel.
	 */
	public PKCS3Alice(String id) {
		super(id);
	}

	/**
	 * Initiates a Diffie-Hellman key agreement protocol on the
	 * provided stream.
	 * <p>Alice does its phase I of the protocol, then write the
	 * resulting public key on the provided stream.
	 * 
	 * @param pOutStream
	 * @param pDhsParams
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 */
	public void initiateDhAgreementProtocol(OutputStream pOutStream, DHParameterSpec pDhsParams)
			throws HobesSecurityException, HobesTransportException{
		protocolPhaseI(pDhsParams);
		ObjectBus.writeWithSource(getId(), pOutStream, getPublicKey());
	}

	/**
	 * Alice completes the Diffie-Hellman key agreement protocol by
	 * when receiving Alice public key, and proceeding to
	 * phase II of the Diffie-Hellman protocol.
	 * <p>After this phase, this actor should find itself in state 
	 * <code>STATE_PHASE_II</code> and be able to communicate over
	 * the established DES channel.
	 * 
	 * @param pOutStream The stream to serialize this actor public key to.
	 * @throws HobesSecurityException When a cryptography error occurs.
	 * @throws HobesTransportException When an I/O error occurs.
	 * @throws HobesDataException When a marshaling error occurs.
	 */
	public void completeDhAgreementProtocol(InputStream pInStream) 
			throws HobesTransportException, HobesSecurityException, HobesDataException{
		
		this.peerEncodedPublicKey = (byte[]) ObjectBus.read(pInStream);
		
		protocolPhaseII(this.peerEncodedPublicKey);
	}

}
