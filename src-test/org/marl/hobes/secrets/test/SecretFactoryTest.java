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
package org.marl.hobes.secrets.test;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.ObjectBus;
import org.marl.hobes.secrets.SecretFactory;

/**
 * Unit test the {@link org.marl.hobes.secrets.SecretFactory} API.
 * 
 * @author chris
 */
public class SecretFactoryTest {

	/**
	 * @param args The unique argument is the temp directory,
	 * which default to <code>$PWD/tmp</code>.
	 */
	public static void main(String[] args) {
		String arg_tmpPath = args.length > 0 ? args [0] : "tmp";
		
		///////////////////////////////////////////////////////////////////
		//
		// Conf.
		//
		String desPath = arg_tmpPath + "/test.des";
		String dhPath = arg_tmpPath + "/test.dh";
		PipedInputStream pis; 
		PipedOutputStream pos;
		DHParameterSpec dhspec, echoDhspec;
		SecretKey etalonSecret, echoSecret;
		
		try{
			///////////////////////////////////////////////////////////////////
			//
			// Testing DES symmetric key stream API
			//
			System.out.println("... Testing DES symmetric keys stream API");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			
			etalonSecret = SecretFactory.createSecretKey();
			System.out.println("... Generated secret key: " + ObjectBus.bytestoHex(etalonSecret.getEncoded()));
			SecretFactory.writeSecretKey(pos, etalonSecret);
			echoSecret = SecretFactory.readSecret(pis);
			System.out.println("... Echo secret key: " + ObjectBus.bytestoHex(echoSecret.getEncoded()));
			assert(Arrays.equals(etalonSecret.getEncoded(), echoSecret.getEncoded()));
			System.out.println("<-- seems ok");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing DES symmetric key file API
			//
			etalonSecret = SecretFactory.createSecretKeyFile(desPath);
			System.out.println("... Generated secret key: " + ObjectBus.bytestoHex(etalonSecret.getEncoded()));
			echoSecret = SecretFactory.createSecretKey(desPath);
			System.out.println("... Echo secret key: " + ObjectBus.bytestoHex(echoSecret.getEncoded()));
			assert(Arrays.equals(etalonSecret.getEncoded(), echoSecret.getEncoded()));
			System.out.println("<-- seems ok");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing reading Diffie-Hellman parameters specification stream API
			//
			System.out.println("... Testing reading Diffie-Hellman parameters specification stream API");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			dhspec = SecretFactory.createDhParams();
			SecretFactory.writeDhParams(pos, dhspec);
			echoDhspec = SecretFactory.readDhParams(pis);
			assert(dhspec.getP().equals(echoDhspec.getP())
					&& dhspec.getG().equals(echoDhspec.getG())
					&& dhspec.getL() == echoDhspec.getL());
			System.out.println("<-- seems ok");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing Diffie-Hellman parameters specification file API
			//
			System.out.println("... Testing Diffie-Hellman parameters specification file API");
			dhspec = SecretFactory.createDhParamsFile(dhPath);
			echoDhspec = SecretFactory.createDhParams(dhPath);
			assert(dhspec.getP().equals(echoDhspec.getP())
					&& dhspec.getG().equals(echoDhspec.getG())
					&& dhspec.getL() == echoDhspec.getL());
			System.out.println("<-- seems ok");
			System.out.println();
		}
		catch(Exception e){
			System.out.println("********** ERROR **********");
			e.printStackTrace();
		}
	}

}
