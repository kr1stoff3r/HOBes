package org.marl.hobes.secrets.test;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;

import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;
import org.marl.hobes.secrets.PKCS3Actor;
import org.marl.hobes.secrets.SecretFactory;
import org.marl.hobes.test.TestObjectType;
import org.marl.hobes.test.TestPreferences;

public class PKCS3AlgorithmTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		TestObjectType etalonData = TestPreferences.getTestObject();
		TestObjectType echoData;

		try{
			PipedInputStream bobInStream, aliceInStream;
			PipedOutputStream bobOutStream, aliceOutStream;
			
			System.out.println("... Testing PKCS3 algorithm");
			System.out.println();
			PKCS3Actor alice = new PKCS3Actor(SourcedObject.GUEST_ID);
			PKCS3Actor bob = new PKCS3Actor(alice.getId());
			
			bob.protocolPhaseI(SecretFactory.createDhParams());
			System.out.println("... Bob initialized its DH public value: "
					+ ObjectBus.bytestoHex(bob.getPublicValue()));
			alice.protocolPhaseI(SecretFactory.createPublicKey(bob.getPublicValue()).getParams());
			System.out.println("... Alice initialized its DH public value: "
					+ ObjectBus.bytestoHex(alice.getPublicValue()));
			System.out.println();

			System.out.println("--> Alice sends its PV to Bob");
			bob.protocolPhaseII(alice.getPublicValue());
			System.out.println("... Bob initialized its secret: "
					+ ObjectBus.bytestoHex(bob.getSecretKey().getEncoded()));
			System.out.println();
			
			System.out.println("--> Bob sends its PV to Alice");
			alice.protocolPhaseII(bob.getPublicValue());
			System.out.println("... Alice initialized its secret: "
					+ ObjectBus.bytestoHex(alice.getSecretKey().getEncoded()));
			System.out.println();
			
			assert(Arrays.equals(alice.getSecretKey().getEncoded(),
					bob.getSecretKey().getEncoded()));
			System.out.println("... The DES channel should now be configured with the agreed secret");
			System.out.println();
			
			aliceOutStream = new PipedOutputStream();
			bobInStream = new PipedInputStream(aliceOutStream);
			System.out.println("... Alice sends and Bob receive");
			alice.write(aliceOutStream, etalonData);
			echoData = (TestObjectType) bob.read(bobInStream);
			assert(etalonData.equals(echoData));
			System.out.println();
			
			bobOutStream = new PipedOutputStream();
			aliceInStream = new PipedInputStream(bobOutStream);
			System.out.println("... Bob sends and Alice receive");
			bob.write(bobOutStream, etalonData);
			echoData = (TestObjectType) alice.read(aliceInStream);
			assert(etalonData.equals(echoData));
			System.out.println();
			System.out.println("done.");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

}
