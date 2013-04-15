package org.marl.hobes.http.test;

import java.net.URL;

import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;
import org.marl.hobes.http.HttpObjectBus;
import org.marl.hobes.http.PKCS3AliceHttp;

public class HttpPKCS3Test {
	
	
	public static void main(String[] args) {
		
		try{
			URL pkcs3BobUrl = new URL("http://localhost:8080/hobes-www/bob");
			System.out.println("... Testing PKCS3 over HTTP transport, using endpoint: " + pkcs3BobUrl.toExternalForm());
			
			PKCS3AliceHttp alice = new PKCS3AliceHttp(SourcedObject.GUEST_ID,
					pkcs3BobUrl,
					HttpObjectBus.DEBUG_TCP_TIMEOUT,
					HttpObjectBus.DEBUG_HTTP_TIMEOUT);
			alice.completeDiffieHellmanProtocol();
			System.out.println("... Alice agreed on shared secret: "
					+ ObjectBus.bytestoHex(alice.getSecretKey().getEncoded()));
			
			System.out.println("... Verifying agreed DES channel");
			String msg = "TestStringMessage";
			Object resp = alice.post(msg, true);
			assert(msg.equals(resp));
			System.out.println("done.");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		

	}
}
