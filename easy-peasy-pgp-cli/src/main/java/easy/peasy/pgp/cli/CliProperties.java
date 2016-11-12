package easy.peasy.pgp.cli;

import java.io.IOException;
import java.util.Properties;

class CliProperties {

	private final Properties properties;

	public CliProperties() {
		this.properties = new Properties();
		try {
			this.properties.load(getClass().getResourceAsStream("cli.properties"));
		} catch (IOException e) {
			// ignore
		}
	}

	public Properties getProperties() {
		return properties;
	}

	public String getVersion() {
		return this.properties.getProperty("version");
	}

	public String getBouncyCastleVersion() {
		return this.properties.getProperty("bc.version");
	}

}
