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
package org.marl.hobes.http.test;

import java.io.Serializable;

import org.marl.hobes.http.HttpObjectBus;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;


public class HttpObjectBusTest {

	public static void main(String[] args) {
		
		try {
			
			Serializable testObject = TestPreferences.getTestObject();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on HTTP transport
			//
			System.out.println("... Testing raw de/serialization on HTTP transport, using echo endpoint: "
					+ TestPreferences.getEchoEndpointUrl().toExternalForm());
			TestObjectType echo = (TestObjectType) HttpObjectBus.post(
					TestPreferences.getEchoEndpointUrl(),
					testObject,
					HttpObjectBus.DEBUG_TCP_TIMEOUT,
					HttpObjectBus.DEBUG_HTTP_TIMEOUT,
					true);
			assert(testObject.equals(echo));
			System.out.println("<-- seems fine");
			System.out.println();
			
			/*
			System.out.println("... Testing DES-encrypted HTTP echo");
			Object desRed = HttpObjectBus.desSendRecieve(TestPreferences.getDesEchoUrl(),
					testObject,
					testObject.getClass(),
					HttpObjectBus.DEBUG_TCP_TIMEOUT,
					HttpObjectBus.DEBUG_HTTP_TIMEOUT,
					SecretManager.getDefaultSecret());
			assert(testObject.equals(desRed));
			System.out.println("<-- Object [" + echo.getName() + "] had a private trip");
			*/
			System.out.println("--done.");
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
