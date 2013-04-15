package org.marl.hobes.secrets;

import java.security.KeyPair;
import java.util.Arrays;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.marl.hobes.ObjectBus;

/**
 * @author chris
 *
 */
public class CreatePVxFilesTool {

	/** Usage: create_pvx [<prefix>] [<DH parameters file>].
	 * 
	 * @param args 
	 */
	public static void main(String[] args) {
		String prefix = args.length > 0 ? args[0] 
				: "src/org/marl/hobes/secrets/bob";
		String dhParamsPath = args.length > 1 ? args[1] 
				: "src/org/marl/hobes/secrets/default.dh";
	
		try{
			
			System.out.println("... Using Diffie-Hellman parameters: "+dhParamsPath);
			DHParameterSpec dhParams = SecretFactory.createDhParams(dhParamsPath);
			KeyPair generatedKeys = SecretFactory.createPVx(dhParams, prefix);
			System.out.println("PV: "
					+ObjectBus.bytestoHex(generatedKeys.getPublic().getEncoded()));
			System.out.println(" x: "
					+ObjectBus.bytestoHex(generatedKeys.getPrivate().getEncoded()));
			
			String pvPath = prefix + ".PV";
			System.out.println("... Verifying public key file: "+pvPath);
			DHPublicKey publicKey = SecretFactory.createPublicKey(pvPath);
			assert(Arrays.equals(publicKey.getEncoded(),
					generatedKeys.getPublic().getEncoded()));
			
			String xPath = prefix + ".x";
			System.out.println("... Verifying private key file: "+xPath);
			DHPrivateKey privateKey = SecretFactory.createPrivateKey(xPath);
			assert(Arrays.equals(privateKey.getEncoded(),
					generatedKeys.getPrivate().getEncoded()));
			
			System.out.println("done.");
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
