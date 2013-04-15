package org.marl.hobes.secrets;

import org.marl.hobes.HobesException;

/**
 * Tool to create a Diffie-Hellman parameters file.
 * 
 * @author chris
 */
public class CreateDhFileTool {

	/** Usage: create_dh_params [<filepath>].
	 * 
	 * @param args An optional file path, 
	 * 	defaults to <code>src/org/marl/hobes/secrets/default.dh</code>.
	 */
	public static void main(String[] args) {
		String sdhFilepath = args.length > 0 ? args[0] 
				: "src/org/marl/hobes/secrets/default.dh";
		
		try {
			System.out.println("... Writting Diffie-Hellman parameters to: "+sdhFilepath);
			SecretFactory.createDhParamsFile(sdhFilepath);
			System.out.println("... Verifying file");
			SecretFactory.createDhParams(sdhFilepath);
			System.out.println("--done.");
		}
		catch (HobesException e) {
			e.printStackTrace();
		}
	}
}
