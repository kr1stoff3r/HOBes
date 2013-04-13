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

import org.marl.hobes.SourcedObject;
import org.marl.hobes.secrets.DesChannel;
import org.marl.hobes.secrets.SecretManager;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;

/**
 * Unit test the {@link org.marl.hobes.secrets.DesChannel} API.
 * 
 * @author chris
 */
public class DesChannelTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		///////////////////////////////////////////////////////////////////
		//
		// Conf.
		//
		PipedInputStream pis; 
		PipedOutputStream pos;
		TestObjectType etalonData = TestPreferences.getTestObject();
		TestObjectType echoData;
		SourcedObject sourcedObj;
		
		try{
			DesChannel desChannel = new DesChannel(SourcedObject.GUEST_ID, 
					SecretManager.getDefaultSecret());
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing DesChannel write/read API consistency on in-memory stream
			//
			System.out.println("... Testing DesChannel write/read API consistency on in-memory stream");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			desChannel.write(pos, etalonData);
			echoData = (TestObjectType) desChannel.read(pis);
			assert(etalonData.equals(echoData));
			System.out.println("... seems fine");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing DesChannel writeWithSource/readWithSourcre API consistency
			// on in-memory stream
			//
			System.out.println("... Testing DesChannel writeWithSource/readWithSourcre API consistency on in-memory stream");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			desChannel.writeWithSource(SourcedObject.GUEST_ID, pos, etalonData);
			sourcedObj = desChannel.readWithSource(pis);
			echoData = (TestObjectType) sourcedObj.getPayload();
			assert(etalonData.equals(echoData));
			System.out.println("... seems fine");
			System.out.println();
			
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
