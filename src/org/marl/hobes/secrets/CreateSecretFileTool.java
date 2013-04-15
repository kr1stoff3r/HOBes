package org.marl.hobes.secrets;

import org.marl.hobes.HobesException;

/**
 * Tool to create a secret key file.
 * <p>The stored key is a symmetric key suitable for DES encryption
 * 
 * @author chris
 *
 */
public class CreateSecretFileTool {

	/** Usage: create_shared_key [<filepath>].
	 * 
	 * @param args An optional file path, 
	 * 	defaults to <code>src/org/marl/hobes/secrets/default.des</code>.
	 */
	public static void main(String[] args) {
		String keyFilepath = args.length > 0 ? args[0] 
				: "src/org/marl/hobes/secrets/default.des";
		
		try {
			System.out.println("... Writting DES key to: "+keyFilepath);
			SecretFactory.createSecretKeyFile(keyFilepath);
			System.out.println("... Verifying file");
			SecretFactory.createSecretKey(keyFilepath);
			System.out.println("--done.");
		}
		catch (HobesException e) {
			e.printStackTrace();
		}
	}
}
