package easy.peasy.pgp.cli;

import static easy.peasy.pgp.cli.Constants.COMMAND_CREATE_KEY_PAIR;
import static easy.peasy.pgp.cli.Constants.COMMAND_DECRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_ENCRYPT;
import static easy.peasy.pgp.cli.Constants.COMMAND_SIGN;
import static easy.peasy.pgp.cli.Constants.COMMAND_VERIFY;
import static easy.peasy.pgp.cli.Constants.OPTION_FILE_IN;
import static easy.peasy.pgp.cli.Constants.OPTION_FILE_OUT;
import static easy.peasy.pgp.cli.Constants.OPTION_PASSWORD;
import static easy.peasy.pgp.cli.Constants.OPTION_PRIVATE_KEY;
import static easy.peasy.pgp.cli.Constants.OPTION_PUBLIC_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.Executor;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CommandLineInterfaceIT {

	private static final String BUILD_DIRECTORY = "buildDirectory";
	private static final String DISTRO_NAME = "distroName";
	private static final String ARTIFACT_NAME = "artifactName";

	private Path workingDirPath;
	private Executor executor;
	private Path samplePayload;

	@BeforeClass
	public static void unpackDistro() throws Exception {
		String buildDirectory = System.getProperty(BUILD_DIRECTORY);
		String distroName = System.getProperty(DISTRO_NAME);

		Path workingDirPath = Paths.get(buildDirectory, "failsafe");
		if (!Files.exists(workingDirPath)) {
			Files.createDirectories(workingDirPath);
		}

		try (ZipFile distroZipFile = new ZipFile(Paths.get(buildDirectory, distroName).toFile())) {
			Enumeration<? extends ZipEntry> entries = distroZipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry zipEntry = entries.nextElement();
				Path zipEntryFile = workingDirPath.resolve(zipEntry.getName());
				if (!Files.exists(zipEntryFile)) {
					if (zipEntry.isDirectory()) {
						Files.createDirectories(zipEntryFile);
					} else {
						Files.createDirectories(zipEntryFile.getParent());
						Files.createFile(zipEntryFile);
						FileOutputStream fileOutputStream = new FileOutputStream(zipEntryFile.toFile());
						Streams.pipeAll(distroZipFile.getInputStream(zipEntry), fileOutputStream);
						fileOutputStream.close();
					}
				}
			}
		}
	}

	@Before
	public void setupExecutor() throws IOException {
		String buildDirectory = System.getProperty(BUILD_DIRECTORY);
		String artifactName = System.getProperty(ARTIFACT_NAME);

		workingDirPath = Paths.get(buildDirectory, "failsafe");
		if (!Files.exists(workingDirPath)) {
			Files.createDirectories(workingDirPath);
		}
		InputStream payloadStream = CommandLineInterfaceIT.class.getResourceAsStream("sample-payload.txt");
		samplePayload = workingDirPath.resolve("sample-payload.txt");
		Streams.pipeAll(payloadStream, new FileOutputStream(samplePayload.toFile()));

		executor = new DefaultExecutor();
		executor.setWorkingDirectory(workingDirPath.resolve(artifactName).toFile());
	}

	@Test
	public void encryptAndDecryptTest() throws Exception {
		Path testWorkingDir = workingDirPath.resolve("encryptAndDecryptTest");
		Path publicKeyPath = testWorkingDir.resolve("public.asc");
		Path privateKeyPath = testWorkingDir.resolve("private.asc");
		Path encrypted = testWorkingDir.resolve("encrypted.asc");
		Path decrypted = testWorkingDir.resolve("decrypted.txt");

		createKeyPair(publicKeyPath, privateKeyPath);
		encrypt(publicKeyPath, samplePayload, encrypted);
		decrypt(privateKeyPath, encrypted, decrypted);
		comparePayloads(decrypted);
	}

	@Test
	public void signAndVerifyTest() throws Exception {
		Path testWorkingDir = workingDirPath.resolve("signAndVerifyTest");
		Path publicKeyPath = testWorkingDir.resolve("public.asc");
		Path privateKeyPath = testWorkingDir.resolve("private.asc");
		Path signed = testWorkingDir.resolve("signed.asc");
		Path verified = testWorkingDir.resolve("verified-payload.txt");

		createKeyPair(publicKeyPath, privateKeyPath);
		sign(privateKeyPath, samplePayload, signed);
		verify(publicKeyPath, signed, verified);
		comparePayloads(verified);
	}

	private void verify(Path publicKeyPath, Path signed, Path verified) throws ExecuteException, IOException {
		String line = new CommandLineBuilder("sh ", ".sh").appendOption(COMMAND_VERIFY).appendOption(OPTION_PUBLIC_KEY, publicKeyPath).appendOption(OPTION_FILE_IN, signed)
				.appendOption(OPTION_FILE_OUT, verified).toString();
		CommandLine cmdLine = CommandLine.parse(line);
		int exitValue = executor.execute(cmdLine);
		assertEquals(0, exitValue);
		assertTrue(Files.exists(verified));
	}

	private void sign(Path privateKeyPath, Path plain, Path signed) throws ExecuteException, IOException {
		String line = new CommandLineBuilder("sh ", ".sh").appendOption(COMMAND_SIGN).appendOption(OPTION_PRIVATE_KEY, privateKeyPath).appendOption(OPTION_PASSWORD, "password")
				.appendOption(OPTION_FILE_IN, plain).appendOption(OPTION_FILE_OUT, signed).toString();
		CommandLine cmdLine = CommandLine.parse(line);
		int exitValue = executor.execute(cmdLine);
		assertEquals(0, exitValue);
		assertTrue(Files.exists(signed));
	}

	private void comparePayloads(Path decrypted) throws IOException, FileNotFoundException {
		ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
		Streams.pipeAll(new FileInputStream(samplePayload.toFile()), plainOut);
		ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
		Streams.pipeAll(new FileInputStream(decrypted.toFile()), decryptedOut);
		assertTrue(Arrays.equals(plainOut.toByteArray(), decryptedOut.toByteArray()));
	}

	private void decrypt(Path privateKeyPath, Path encrypted, Path decrypted) throws ExecuteException, IOException {
		String line = new CommandLineBuilder("sh ", ".sh").appendOption(COMMAND_DECRYPT).appendOption(OPTION_PRIVATE_KEY, privateKeyPath).appendOption(OPTION_PASSWORD, "password")
				.appendOption(OPTION_FILE_IN, encrypted).appendOption(OPTION_FILE_OUT, decrypted).toString();
		CommandLine cmdLine = CommandLine.parse(line);
		int exitValue = executor.execute(cmdLine);
		assertEquals(0, exitValue);
		assertTrue(Files.exists(decrypted));
	}

	private void encrypt(Path publicKeyPath, Path plain, Path encrypted) throws ExecuteException, IOException {
		String line = new CommandLineBuilder("sh ", ".sh").appendOption(COMMAND_ENCRYPT).appendOption(OPTION_PUBLIC_KEY, publicKeyPath).appendOption(OPTION_FILE_IN, plain)
				.appendOption(OPTION_FILE_OUT, encrypted).toString();
		CommandLine cmdLine = CommandLine.parse(line);
		int exitValue = executor.execute(cmdLine);
		assertEquals(0, exitValue);
		assertTrue(Files.exists(encrypted));
	}

	private void createKeyPair(Path publicKeyPath, Path privateKeyPath) throws ExecuteException, IOException {
		String line = new CommandLineBuilder("sh ", ".sh").appendOption(COMMAND_CREATE_KEY_PAIR).appendOption(OPTION_PUBLIC_KEY, publicKeyPath)
				.appendOption(OPTION_PRIVATE_KEY, privateKeyPath).appendOption(OPTION_PASSWORD, "password").toString();
		CommandLine cmdLine = CommandLine.parse(line);
		int exitValue = executor.execute(cmdLine);
		assertEquals(0, exitValue);
		assertTrue(Files.exists(publicKeyPath));
		assertTrue(Files.exists(privateKeyPath));
	}

}
