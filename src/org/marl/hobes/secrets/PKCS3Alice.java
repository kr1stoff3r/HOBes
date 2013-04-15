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

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.interfaces.DHPublicKey;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;

public class PKCS3Alice extends PKCS3Actor {

	private DHPublicKey trustedPV;
	
	/**
	 * Creates an Alice PKCS3 actor.
	 * 
	 * @param id An identifier to refer to the corresponding
	 * DES channel.
	 * @throws HobesSecurityException 
	 * @throws HobesDataException 
	 * @throws HobesTransportException 
	 */
	public PKCS3Alice(String id) throws HobesException {
		super(id);
		this.trustedPV = SecretManager.getTrustedPublicValue();
	}

	/**
	 * @throws InvalidAlgorithmParameterException
	 * @throws HobesException
	 */
	public void protocolPhaseI()
			throws HobesException {
		super.protocolPhaseI(this.trustedPV.getParams());
	}

	@Override
	public void protocolPhaseII(byte[] bobEncodedPV)
			throws HobesException {
		if (SecretManager.isTrustedPublicValue(bobEncodedPV)){
			super.protocolPhaseII(bobEncodedPV);
		}
		else throw new HobesSecurityException("UNTRUSTED PUBLIC VALUE!");
	}
	
}
