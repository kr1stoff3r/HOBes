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

import org.marl.hobes.http.DesObjectBusHttp;
import org.marl.hobes.http.HttpObjectBus;
import org.marl.hobes.secrets.SecretManager;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;


public class HttpDesObjectBusTest {

	public static void main(String[] args) {
		
		try {
			
			TestObjectType testObject = TestPreferences.getTestObject();
			
			///////////////////////////////////////////////////////////////////
			//
			// Testing raw de/serialization on DES encrypted HTTP transport
			//
			System.out.println("... Testing raw de/serialization on DES encrypted HTTP transport, using echo endpoint: "
					+ TestPreferences.getEchoEndpointUrl().toExternalForm());
			TestObjectType echo = (TestObjectType) DesObjectBusHttp.post(
					TestPreferences.getEchoEndpointUrl(),
					testObject,
					HttpObjectBus.DEBUG_TCP_TIMEOUT,
					HttpObjectBus.DEBUG_HTTP_TIMEOUT,
					true,
					SecretManager.getDefaultSecret());
			assert(testObject.equals(echo));
			System.out.println("<-- seems fine");
			
			System.out.println("... Testing raw de/serialization on DES encrypted HTTP transport, using endpoint: "
					+ TestPreferences.getTestDesUrl().toExternalForm());
			echo = (TestObjectType) DesObjectBusHttp.post(
					TestPreferences.getTestDesUrl(),
					testObject,
					HttpObjectBus.DEBUG_TCP_TIMEOUT,
					HttpObjectBus.DEBUG_HTTP_TIMEOUT,
					true,
					SecretManager.getDefaultSecret());
			assert(echo.getNumber() == (testObject.getNumber()+1));
			System.out.println("<-- seems really fine");
			System.out.println();
			
			
			System.out.println("--done.");
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
