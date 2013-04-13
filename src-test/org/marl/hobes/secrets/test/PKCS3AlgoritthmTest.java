package org.marl.hobes.secrets.test;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;
import org.marl.hobes.secrets.PKCS3Alice;
import org.marl.hobes.secrets.PKCS3Bob;
import org.marl.hobes.secrets.SecretManager;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;

public class PKCS3AlgoritthmTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		///////////////////////////////////////////////////////////////////
		//
		// Conf.
		//
		PipedInputStream bobInStream; // from Alice 
		PipedOutputStream bobOutStream; // where Alice writes
		PipedInputStream aliceInStream; // from Bob
		PipedOutputStream aliceOutStream; // where Bob writes
		
		TestObjectType etalonData = TestPreferences.getTestObject();
		TestObjectType echoData;

		try{
			bobInStream = new PipedInputStream();
			bobOutStream = new PipedOutputStream(bobInStream);
			aliceInStream = new PipedInputStream();
			aliceOutStream = new PipedOutputStream(aliceInStream);
			
			System.out.println("... Testing PKCS3 actors API on in-memory streams");
			PKCS3Alice alice = new PKCS3Alice(SourcedObject.GUEST_ID); 
			alice.initiateDhAgreementProtocol(bobOutStream, SecretManager.getDefaultDhParams());
			System.out.println("... Alice initialized its DH public key: "
					+ ObjectBus.bytestoHex(alice.getPublicKey()));
			
			System.out.println("--> Alice sends its public key to Bob");
			PKCS3Bob bob = PKCS3Bob.initiateDhAgreementProtocol(bobInStream);
			System.out.println("<-- Bob initialized its DH public key: "
					+ ObjectBus.bytestoHex(bob.getPublicKey()));
			
			bob.completeDhAgreementProtocol(aliceOutStream);
			System.out.println("--> Bob sends its public key to Alice");
			System.out.println("... Bob initialized its secret: "
					+ ObjectBus.bytestoHex(bob.getSharedSecret().getEncoded()));
			
			alice.completeDhAgreementProtocol(aliceInStream);
			System.out.println("... Alice initialized its secret: "
					+ ObjectBus.bytestoHex(alice.getSharedSecret().getEncoded()));
			System.out.println("... DES channel should be setup with agreed secret");
			System.out.println();
			
			bobInStream = new PipedInputStream();
			bobOutStream = new PipedOutputStream(bobInStream);
			aliceInStream = new PipedInputStream();
			aliceOutStream = new PipedOutputStream(aliceInStream);
			
			System.out.println("... Alice sends and Bob receive");
			alice.write(bobOutStream, etalonData);
			echoData = (TestObjectType) bob.read(bobInStream);
			assert(etalonData.equals(echoData));
			System.out.println("... Bob sends and Alice receive");
			bob.write(aliceOutStream, etalonData);
			echoData = (TestObjectType) alice.read(aliceInStream);
			assert(etalonData.equals(echoData));
			System.out.println("... All seem fine.");
			System.out.println();
			
			System.out.println("done.");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

}
