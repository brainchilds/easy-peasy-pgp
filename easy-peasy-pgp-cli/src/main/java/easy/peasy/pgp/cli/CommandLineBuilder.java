package easy.peasy.pgp.cli;

import static easy.peasy.pgp.cli.Constants.CLI_NAME;

import org.apache.commons.cli.Option;

class CommandLineBuilder {
	private final StringBuilder stringBuilder;

	public CommandLineBuilder() {
		this.stringBuilder = new StringBuilder(CLI_NAME);
	}

	public CommandLineBuilder(String prefix, String suffix) {
		this.stringBuilder = new StringBuilder();
		this.stringBuilder.append(prefix).append(CLI_NAME).append(suffix);
	}

	public CommandLineBuilder appendOption(Option option) {
		return appendOption(option, null);
	}

	public CommandLineBuilder appendOption(Option option, Object value) {
		if (option.hasLongOpt()) {
			stringBuilder.append(" --").append(option.getLongOpt());
		} else {
			stringBuilder.append(" -").append(option.getOpt());
		}
		if (value != null) {
			stringBuilder.append(" ").append(value.toString());
		}
		return this;
	}

	@Override
	public String toString() {
		return stringBuilder.toString();
	}

}
