package org.brainchilds.easy.peasy.pgp.cli;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;

class Constants {
	public static final String CLI_NAME = "easy-peasy-pgp";

	public static final String OPTION_NAME_PRIVATE_KEY = "privateKey";
	public static final String OPTION_NAME_PUBLIC_KEY = "publicKey";
	public static final String OPTION_NAME_FILE_OUT = "fileOut";
	public static final String OPTION_NAME_FILE_IN = "fileIn";
	public static final String OPTION_NAME_SIGNATURE_IN = "signatureIn";
	public static final String OPTION_NAME_DETACHED_SIGNATURE = "detached";
	public static final String OPTION_NAME_PASSWORD = "password";
	public static final String OPTION_NAME_VERBOSE = "verbose";
	public static final String OPTION_NAME_HELP = "help";
	public static final String OPTION_NAME_VERSION = "version";

	public static final String COMMAND_NAME_ENCRYPT = "encrypt";
	public static final String COMMAND_NAME_DECRYPT = "decrypt";
	public static final String COMMAND_NAME_SIGN = "sign";
	public static final String COMMAND_NAME_VERIFY = "verify";
	public static final String COMMAND_NAME_CREATE_KEY_PAIR = "createKeyPair";

	protected static final Option COMMAND_ENCRYPT = Option.builder("e").longOpt(COMMAND_NAME_ENCRYPT).desc("Encrypt data").required().hasArg(false).build();
	protected static final Option COMMAND_DECRYPT = Option.builder("d").longOpt(COMMAND_NAME_DECRYPT).desc("Decrypt data").required().hasArg(false).build();
	protected static final Option COMMAND_SIGN = Option.builder("s").longOpt(COMMAND_NAME_SIGN).desc("Sign data").required().hasArg(false).build();
	protected static final Option COMMAND_VERIFY = Option.builder("v").longOpt(COMMAND_NAME_VERIFY).desc("Verify signed data").required().hasArg(false).build();
	protected static final Option COMMAND_CREATE_KEY_PAIR = Option.builder("ckp").longOpt(COMMAND_NAME_CREATE_KEY_PAIR).desc("Create RSA keypair").required().hasArg(false).build();

	protected static final Option OPTION_PRIVATE_KEY = Option.builder("prKey").longOpt(OPTION_NAME_PRIVATE_KEY).desc("The private key file").hasArg().required(false).build();
	protected static final Option OPTION_PUBLIC_KEY = Option.builder("puKey").longOpt(OPTION_NAME_PUBLIC_KEY).desc("The public key file").hasArg().required(false).build();
	protected static final Option OPTION_FILE_OUT = Option.builder(OPTION_NAME_FILE_OUT).desc("The output file").hasArg().required(false).build();
	protected static final Option OPTION_FILE_IN = Option.builder(OPTION_NAME_FILE_IN).desc("The input file").hasArg().required(false).build();
	protected static final Option OPTION_SIGNATURE_IN = Option.builder("sigIn").longOpt(OPTION_NAME_SIGNATURE_IN).desc("The detached signature input file").hasArg().required(false).build();
	protected static final Option OPTION_DETACHED_SIGNATURE = Option.builder(OPTION_NAME_DETACHED_SIGNATURE).longOpt(OPTION_NAME_DETACHED_SIGNATURE).desc("If the signature shall be detached").hasArg(false).required(false).build();
	protected static final Option OPTION_PASSWORD = Option.builder("pw").longOpt(OPTION_NAME_PASSWORD).argName(OPTION_NAME_PASSWORD).desc("The password for the given private key")
			.hasArg().required(false).build();
	protected static final Option OPTION_VERBOSE = Option.builder(OPTION_NAME_VERBOSE).longOpt(OPTION_NAME_VERBOSE).desc("Enable verbose output").hasArg(false).required(false)
			.build();
	protected static final Option OPTION_HELP = Option.builder("h").longOpt(OPTION_NAME_HELP).desc("Show help").hasArg(false).required(false).build();
	protected static final Option OPTION_VERSION = Option.builder(OPTION_NAME_VERSION).longOpt(OPTION_NAME_VERSION).desc("Show cli version").hasArg(false).required(false).build();

	protected static final OptionGroup COMMANDS = new OptionGroup();
	static {
		COMMANDS.setRequired(false);
		COMMANDS.addOption(COMMAND_CREATE_KEY_PAIR);
		COMMANDS.addOption(COMMAND_ENCRYPT);
		COMMANDS.addOption(COMMAND_DECRYPT);
		COMMANDS.addOption(COMMAND_SIGN);
		COMMANDS.addOption(COMMAND_VERIFY);
	}

	protected static final Options ALL_OPTIONS = new Options();
	static {
		ALL_OPTIONS.addOptionGroup(COMMANDS);
		ALL_OPTIONS.addOption(OPTION_PASSWORD);
		ALL_OPTIONS.addOption(OPTION_FILE_IN);
		ALL_OPTIONS.addOption(OPTION_FILE_OUT);
		ALL_OPTIONS.addOption(OPTION_PRIVATE_KEY);
		ALL_OPTIONS.addOption(OPTION_PUBLIC_KEY);
		ALL_OPTIONS.addOption(OPTION_DETACHED_SIGNATURE);
		ALL_OPTIONS.addOption(OPTION_SIGNATURE_IN);
		ALL_OPTIONS.addOption(OPTION_VERBOSE);
		ALL_OPTIONS.addOption(OPTION_HELP);
		ALL_OPTIONS.addOption(OPTION_VERSION);
	}

	protected static final Options FIRST_CLASS_OPTIONS = new Options();
	static {
		FIRST_CLASS_OPTIONS.addOptionGroup(COMMANDS);
		FIRST_CLASS_OPTIONS.addOption(OPTION_HELP);
		FIRST_CLASS_OPTIONS.addOption(OPTION_VERSION);
	}

	protected static final Option[] REQUIRED_OPTIONS_VERIFY = { OPTION_FILE_IN, OPTION_FILE_OUT, OPTION_PUBLIC_KEY, OPTION_SIGNATURE_IN };
	protected static final Option[] REQUIRED_OPTIONS_SIGN = { OPTION_FILE_IN, OPTION_FILE_OUT, OPTION_PRIVATE_KEY, OPTION_PASSWORD, OPTION_DETACHED_SIGNATURE };
	protected static final Option[] REQUIRED_OPTIONS_DECRYPT = { OPTION_FILE_IN, OPTION_FILE_OUT, OPTION_PRIVATE_KEY, OPTION_PASSWORD };
	protected static final Option[] REQUIRED_OPTIONS_ENCRYPT = { OPTION_FILE_IN, OPTION_FILE_OUT, OPTION_PUBLIC_KEY };
	protected static final Option[] REQUIRED_OPTIONS_CREATE_KEY_PAIR = { OPTION_PUBLIC_KEY, OPTION_PRIVATE_KEY, OPTION_PASSWORD };

	private Constants() {
		// util
	}
}
