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


import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.HobesException;

/** Tools to generate and store DES symmetric keys and Diffie-Hellman parameters.
 * 
 * @author chris
 */
public class SecretManager {

	/** Default DES secret.
	 * 
	 * @return
	 * @throws HobesException
	 */
	public static SecretKey getDefaultSecret() throws HobesException{
		return SecretFactory.readSecret(
				SecretManager.class.getClassLoader()
				.getResourceAsStream("org/marl/hobes/secrets/default.des")
				);
	}
	
	/** Default DH parameters.
	 * 
	 * @return
	 * @throws HobesException
	 */
	public static DHParameterSpec getDefaultDhParams() throws HobesException{
		return SecretFactory.readDhSpec(
				SecretManager.class.getClassLoader().
				getResourceAsStream("org/marl/hobes/secrets/default.dh")
				);
	}
}
