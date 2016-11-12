package easy.peasy.pgp.cli;

import static easy.peasy.pgp.cli.Constants.ALL_OPTIONS;
import static easy.peasy.pgp.cli.Constants.CLI_NAME;
import static easy.peasy.pgp.cli.Constants.COMMAND_CREATE_KEY_PAIR;
import static easy.peasy.pgp.cli.Constants.COMMAND_DECRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_ENCRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_NAME_CREATE_KEY_PAIR;
import static easy.peasy.pgp.cli.Constants.COMMAND_NAME_DECRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_NAME_ENCRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_NAME_SIGN;
import static easy.peasy.pgp.cli.Constants.COMMAND_NAME_VERIFY;
import static easy.peasy.pgp.cli.Constants.COMMAND_SIGN;
import static easy.peasy.pgp.cli.Constants.COMMAND_VERIFY;
import static easy.peasy.pgp.cli.Constants.FIRST_CLASS_OPTIONS;
import static easy.peasy.pgp.cli.Constants.OPTION_HELP;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_FILE_IN;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_FILE_OUT;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_HELP;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_PASSWORD;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_PRIVATE_KEY;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_PUBLIC_KEY;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_VERBOSE;
import static easy.peasy.pgp.cli.Constants.OPTION_NAME_VERSION;
import static easy.peasy.pgp.cli.Constants.OPTION_VERBOSE;
import static easy.peasy.pgp.cli.Constants.REQUIRED_OPTIONS_CREATE_KEY_PAIR;
import static easy.peasy.pgp.cli.Constants.REQUIRED_OPTIONS_DECRYPT;
import static easy.peasy.pgp.cli.Constants.REQUIRED_OPTIONS_ENCRYPT;
import static easy.peasy.pgp.cli.Constants.REQUIRED_OPTIONS_SIGN;
import static easy.peasy.pgp.cli.Constants.REQUIRED_OPTIONS_VERIFY;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import easy.peasy.pgp.bc.BcPgpKeyPairGenerator;
import easy.peasy.pgp.bc.BcPgpPrivateKeyOperations;
import easy.peasy.pgp.bc.BcPgpPublicKeyOperations;
import easy.peasy.pgp.bc.PrivateKeyRing;
import easy.peasy.pgp.bc.PublicKeyRing;

class CommandLineHandler {

	private final String[] args;
	private CommandLine commandLine;
	private boolean verbose;
	private boolean help;

	public CommandLineHandler(String[] args) {
		this.args = args;
	}

	public int parseAndExecute() {
		try {
			CommandLineParser parser = new DefaultParser();
			this.commandLine = parser.parse(ALL_OPTIONS, this.args);
		} catch (ParseException e) {
			if (checkArgsManuallyFor(OPTION_VERBOSE)) {
				e.printStackTrace();
			}
			printOptions(CLI_NAME, ALL_OPTIONS);
			return 1;
		}

		this.verbose = commandLine.hasOption(OPTION_NAME_VERBOSE);
		this.help = commandLine.hasOption(OPTION_NAME_HELP);

		if (commandLine.hasOption(COMMAND_NAME_CREATE_KEY_PAIR)) {
			return createKeyPair();
		} else if (commandLine.hasOption(COMMAND_NAME_ENCRYPT)) {
			return encrypt();
		} else if (commandLine.hasOption(COMMAND_NAME_DECRYPT)) {
			return decrypt();
		} else if (commandLine.hasOption(COMMAND_NAME_SIGN)) {
			return sign();
		} else if (commandLine.hasOption(COMMAND_NAME_VERIFY)) {
			return verify();
		} else if (commandLine.hasOption(OPTION_NAME_HELP)) {
			printHelpForAllCommands();
		} else if (commandLine.hasOption(OPTION_NAME_VERSION)) {
			printVersions();
		} else {
			printOptions(CLI_NAME, FIRST_CLASS_OPTIONS);
		}
		return 0;
	}

	private boolean checkArgsManuallyFor(Option option) {
		for (String arg : this.args) {
			if (arg.equals("-" + option.getOpt()) || arg.equals("--" + option.getLongOpt())) {
				return true;
			}
		}
		return false;
	}

	private int verify() {
		if (this.help) {
			printHelpForCommand(COMMAND_VERIFY, REQUIRED_OPTIONS_VERIFY);
		} else {
			try {
				if (!hasRequiredOptions(REQUIRED_OPTIONS_VERIFY)) {
					printException(COMMAND_VERIFY, REQUIRED_OPTIONS_VERIFY, new IllegalArgumentException("Missing requirement argument"));
					return 1;
				}

				Path publicKeyFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PUBLIC_KEY));
				Path inputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_IN));
				Path outputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_OUT));
				BcPgpPublicKeyOperations encryptor = new BcPgpPublicKeyOperations(new PublicKeyRing(new FileInputStream(publicKeyFile.toFile())));
				boolean verified = encryptor.verify(new FileInputStream(inputFile.toFile()), new FileOutputStream(outputFile.toFile()));
				if (verified) {
					System.out.println("Verified signature");
				} else {
					System.out.println("Could not verify signature");
				}
			} catch (Exception e) {
				printException(COMMAND_VERIFY, REQUIRED_OPTIONS_VERIFY, e);
				return 1;
			}
		}
		return 0;
	}

	private int sign() {
		if (this.help) {
			printHelpForCommand(COMMAND_SIGN, REQUIRED_OPTIONS_SIGN);
		} else {
			try {
				if (!hasRequiredOptions(REQUIRED_OPTIONS_SIGN)) {
					printException(COMMAND_SIGN, REQUIRED_OPTIONS_SIGN, new IllegalArgumentException("Missing requirement argument"));
					return 1;
				}
				Path privateKeyFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PRIVATE_KEY));
				String password = commandLine.getOptionValue(OPTION_NAME_PASSWORD);
				Path inputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_IN));
				Path outputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_OUT));
				BcPgpPrivateKeyOperations decryptor = new BcPgpPrivateKeyOperations(new PrivateKeyRing(new FileInputStream(privateKeyFile.toFile()), password));
				decryptor.sign(new FileInputStream(inputFile.toFile()), new FileOutputStream(outputFile.toFile()));
			} catch (Exception e) {
				printException(COMMAND_SIGN, REQUIRED_OPTIONS_SIGN, e);
				return 1;
			}
		}
		return 0;
	}

	private int decrypt() {
		if (this.help) {
			printHelpForCommand(COMMAND_DECRYPT, REQUIRED_OPTIONS_DECRYPT);
		} else {
			try {
				if (!hasRequiredOptions(REQUIRED_OPTIONS_DECRYPT)) {
					printException(COMMAND_DECRYPT, REQUIRED_OPTIONS_DECRYPT, new IllegalArgumentException("Missing requirement argument"));
					return 1;
				}

				Path privateKeyFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PRIVATE_KEY));
				String password = commandLine.getOptionValue(OPTION_NAME_PASSWORD);
				Path inputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_IN));
				Path outputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_OUT));
				BcPgpPrivateKeyOperations decryptor = new BcPgpPrivateKeyOperations(new PrivateKeyRing(new FileInputStream(privateKeyFile.toFile()), password));
				decryptor.decrypt(new FileInputStream(inputFile.toFile()), new FileOutputStream(outputFile.toFile()));
			} catch (Exception e) {
				printException(COMMAND_DECRYPT, REQUIRED_OPTIONS_DECRYPT, e);
				return 1;
			}
		}
		return 0;
	}

	private int encrypt() {
		if (this.help) {
			printHelpForCommand(COMMAND_ENCRYPT, REQUIRED_OPTIONS_ENCRYPT);
		} else {
			try {
				if (!hasRequiredOptions(REQUIRED_OPTIONS_ENCRYPT)) {
					printException(COMMAND_ENCRYPT, REQUIRED_OPTIONS_ENCRYPT, new IllegalArgumentException("Missing requirement argument"));
					return 1;
				}
				Path publicKeyFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PUBLIC_KEY));
				Path inputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_IN));
				Path outputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_FILE_OUT));
				BcPgpPublicKeyOperations encryptor = new BcPgpPublicKeyOperations(new PublicKeyRing(new FileInputStream(publicKeyFile.toFile())));
				encryptor.encrypt(new FileInputStream(inputFile.toFile()), new FileOutputStream(outputFile.toFile()));
			} catch (Exception e) {
				printException(COMMAND_ENCRYPT, REQUIRED_OPTIONS_ENCRYPT, e);
				return 1;
			}
		}
		return 0;
	}

	private int createKeyPair() {
		if (this.help) {
			printHelpForCommand(COMMAND_CREATE_KEY_PAIR, REQUIRED_OPTIONS_CREATE_KEY_PAIR);
		} else {
			try {
				if (!hasRequiredOptions(REQUIRED_OPTIONS_CREATE_KEY_PAIR)) {
					printException(COMMAND_CREATE_KEY_PAIR, REQUIRED_OPTIONS_CREATE_KEY_PAIR, new IllegalArgumentException("Missing requirement argument"));
					return 1;
				}
				Path privateKeyOutputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PRIVATE_KEY));
				Path publicKeyOutputFile = resolveFile(commandLine.getOptionValue(OPTION_NAME_PUBLIC_KEY));
				String password = commandLine.getOptionValue(OPTION_NAME_PASSWORD);
				BcPgpKeyPairGenerator keyPairGenerator = new BcPgpKeyPairGenerator();
				keyPairGenerator.createKeyPair("user", new FileOutputStream(publicKeyOutputFile.toFile()), new FileOutputStream(privateKeyOutputFile.toFile()), password);
			} catch (Exception e) {
				printException(COMMAND_CREATE_KEY_PAIR, REQUIRED_OPTIONS_CREATE_KEY_PAIR, e);
				return 1;
			}
		}
		return 0;
	}

	private Path resolveFile(String fileName) throws IOException {
		try {
			Path privateKeyOutputFile = Paths.get(fileName);
			Files.createDirectories(privateKeyOutputFile.getParent());
			return privateKeyOutputFile;
		} catch (Exception e) {
			String msg = "Filename " + fileName;
			if (e.getMessage() != null) {
				msg += ": " + e.getMessage();
			}
			throw new IOException(msg, e);
		}
	}

	private boolean hasRequiredOptions(Option[] options) {
		for (Option option : options) {
			if (!this.commandLine.hasOption(option.getOpt())) {
				return false;
			}
		}
		return true;
	}

	private void printHelpForAllCommands() {
		printCommandExample(COMMAND_CREATE_KEY_PAIR, REQUIRED_OPTIONS_CREATE_KEY_PAIR);
		printCommandExample(COMMAND_ENCRYPT, REQUIRED_OPTIONS_ENCRYPT);
		printCommandExample(COMMAND_DECRYPT, REQUIRED_OPTIONS_DECRYPT);
		printCommandExample(COMMAND_SIGN, REQUIRED_OPTIONS_SIGN);
		printCommandExample(COMMAND_VERIFY, REQUIRED_OPTIONS_VERIFY);
		System.out.println();
		printOptions(CLI_NAME, ALL_OPTIONS);
	}

	private void printHelpForCommand(Option command, Option[] requiredOptions) {
		printCommandExample(command, requiredOptions);
		System.out.println();
		printOptions(buildNameWithCommand(command), requiredOptions);

	}

	private void printCommandExample(Option command, Option[] requiredOptions) {
		System.out.println(command.getDescription());
		CommandLineBuilder commandLineBuilder = new CommandLineBuilder();
		commandLineBuilder.appendOption(command);
		for (Option option : requiredOptions) {
			commandLineBuilder.appendOption(option, "<arg>");
		}
		System.out.println("\t" + commandLineBuilder);
	}

	private void printException(Option command, Option[] optionsArray, Exception exception) {
		if (verbose) {
			StringBuilder arguments = new StringBuilder("Arguments: ");
			for (String arg : args) {
				arguments.append(arg).append(" ");
			}
			System.out.println(arguments);
			if (exception != null) {
				exception.printStackTrace();
			}
		}
		Options options = new Options();
		for (Option option : optionsArray) {
			options.addOption(option);
		}
		options.addOption(OPTION_HELP);
		options.addOption(OPTION_VERBOSE);
		printOptions(buildNameWithCommand(command), options);
	}

	private void printOptions(String name, Option[] optionsArray) {
		Options options = new Options();
		for (Option option : optionsArray) {
			options.addOption(option);
		}
		printOptions(name, options);
	}

	private void printOptions(String name, Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp(name, options);
	}

	private void printVersions() {
		CliProperties properties = new CliProperties();
		System.out.println("Version " + properties.getVersion());
		System.out.println("Bouncy Castle Version " + properties.getBouncyCastleVersion());
	}

	private String buildNameWithCommand(Option command) {
		return CLI_NAME + " --" + command.getLongOpt();
	}

}
