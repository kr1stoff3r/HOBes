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
package org.marl.hobes.test;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;

/**
 * Unit test the {@link org.marl.hobes.ObjectBus} API.
 * 
 * @author chris
 */
public class ObjectBusTest {

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
		String szPath = arg_tmpPath + "/obj.ser";
		String sszPath = arg_tmpPath + "/sobj.ser";
		PipedInputStream pis; 
		PipedOutputStream pos;
		TestObjectType etalonData = TestPreferences.getTestObject();
		Object echoData;
		SourcedObject sourcedObj;
		
		try{
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on in-memory stream
			//
			System.out.println("... Testing raw de/serialization on in-memory stream");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			ObjectBus.write(pos, etalonData);
			echoData = (TestObjectType) ObjectBus.read(pis);
			assert(echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice read/write");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on file
			//
			System.out.println("... Testing raw de/serialization on file");
			ObjectBus.write(szPath, etalonData);
			echoData = (TestObjectType) ObjectBus.read(szPath);
			assert(echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice read/write");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on in-memory stream
			//
			System.out.println("... Testing sourced de/serialization on in-memory stream");
			pis = new PipedInputStream();
			pos = new PipedOutputStream(pis);
			ObjectBus.writeWithSource(SourcedObject.GUEST_ID, pos, etalonData);
			sourcedObj = SourcedObject.class.cast(ObjectBus.readWithSource(pis));
			echoData = sourcedObj.getPayload();
			assert(echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice read/write");
			System.out.println();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing sourced de/serialization on file
			//
			System.out.println("... Testing sourced de/serialization on file");
			ObjectBus.writeWithSource(SourcedObject.GUEST_ID, sszPath, etalonData);
			sourcedObj = SourcedObject.class.cast(ObjectBus.readWithSource(sszPath));
			echoData = sourcedObj.getPayload();
			assert(echoData.getClass().equals(TestObjectType.class));
			assert (etalonData.equals(echoData));
			System.out.println("<-- Object seems to had a nice read/write");
			System.out.println();
			
		}
		catch(Exception e){
			System.out.println("********** ERROR **********");
			e.printStackTrace();
		}
	}

}
