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

import javax.crypto.SealedObject;

import org.marl.hobes.SourcedObject;
import org.marl.hobes.secrets.DesObjectBus;
import org.marl.hobes.secrets.SecretManager;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;

/**
 * Unit test the {@link org.marl.hobes.secrets.DesObjectBus} API.
 * 
 * @author chris
 */
public class DesObjectBusTest {

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
		String szPath = arg_tmpPath + "/obj.des";
		String sszPath = arg_tmpPath + "/obj.sdes";
		PipedInputStream pis; 
		PipedOutputStream pos;
		TestObjectType etalonData = TestPreferences.getTestObject();
		Object echoData;
		SourcedObject sourcedObj;
		
		try{
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on DES encrypted in-memory stream
			//
			System.out.println("... Testing raw de/serialization on DES encrypted in-memory stream");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			DesObjectBus.write(pos, etalonData, SecretManager.getDefaultSecret());
			echoData = (TestObjectType) DesObjectBus.read(pis, SecretManager.getDefaultSecret());
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();
		
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on DES encrypted file
			//
			System.out.println("... Testing raw de/serialization on DES encrypted file");
			DesObjectBus.write(szPath, etalonData, SecretManager.getDefaultSecret());
			echoData = (TestObjectType) DesObjectBus.read(szPath, SecretManager.getDefaultSecret());
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();

			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on DES encrypted in-memory stream (blind)
			//
			System.out.println("... Testing sourced de/serialization on DES encrypted in-memory stream (blind)");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			DesObjectBus.writeWithSource(SourcedObject.GUEST_ID,
					pos, 
					etalonData,
					SecretManager.getDefaultSecret());
			sourcedObj = DesObjectBus.readWithSource(pis);
			echoData = DesObjectBus.decipher( (SealedObject) sourcedObj.getPayload(), 
					SecretManager.getDefaultSecret());
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on DES encrypted in-memory stream (aware)
			//
			System.out.println("... Testing sourced de/serialization on DES encrypted in-memory stream (aware)");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			DesObjectBus.writeWithSource(SourcedObject.GUEST_ID,
					pos, 
					etalonData,
					SecretManager.getDefaultSecret());
			sourcedObj = DesObjectBus.readWithSource(pis, SecretManager.getDefaultSecret());
			echoData = sourcedObj.getPayload();
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on DES encrypted file (blind)
			//
			System.out.println("... Testing sourced de/serialization on DES encrypted file (blind)");
			DesObjectBus.writeWithSource(SourcedObject.GUEST_ID,
					sszPath, 
					etalonData,
					SecretManager.getDefaultSecret());
			sourcedObj = DesObjectBus.readWithSource(sszPath);
			echoData = DesObjectBus.decipher((SealedObject) sourcedObj.getPayload(), SecretManager.getDefaultSecret());
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();
		
			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on DES encrypted file (aware)
			//
			System.out.println("... Testing sourced de/serialization on DES encrypted file (aware)");
			DesObjectBus.writeWithSource(SourcedObject.GUEST_ID,
					sszPath, 
					etalonData,
					SecretManager.getDefaultSecret());
			sourcedObj = DesObjectBus.readWithSource(sszPath, SecretManager.getDefaultSecret());
			echoData = sourcedObj.getPayload();
			assert (echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice private read/write");
			System.out.println();
		
		}
		catch(Exception e){
			System.out.println("********** ERROR **********");
			e.printStackTrace();
		}
	}

}
