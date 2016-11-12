package easy.peasy.pgp.cli;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		CommandLineHandler commandLineHandler = new CommandLineHandler(args);
		int exitStatus = commandLineHandler.parseAndExecute();
		System.exit(exitStatus);
	}

}
