package org.brainchilds.easy.peasy.pgp.bc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;

public class KeyPairGeneratorTest {
	private BcPgpKeyPairGenerator keyPairGenerator;

	@Before
	public void createKeyPairGenerator() {
		keyPairGenerator = new BcPgpKeyPairGenerator();
	}

	@Test
	public void streamBasedKeyPairCreation() throws Exception {
		ByteArrayOutputStream publicKeyOut = new ByteArrayOutputStream();
		ByteArrayOutputStream privateKeyOut = new ByteArrayOutputStream();

		String keyPairId = keyPairGenerator.createKeyPair("userId", "password", publicKeyOut, privateKeyOut);

		publicKeyOut.close();
		privateKeyOut.close();

		// assert that keys are contained
		try (ByteArrayInputStream privateKeyIn = new ByteArrayInputStream(privateKeyOut.toByteArray())) {
			PrivateKeyRing privateKeyRing = new PrivateKeyRing(privateKeyIn, "password");
			assertNotNull(privateKeyRing.getKeyById(keyPairId));
		}
		try (ByteArrayInputStream publicKeyIn = new ByteArrayInputStream(publicKeyOut.toByteArray())) {
			PublicKeyRing publicKeyRing = new PublicKeyRing(publicKeyIn);
			assertNotNull(publicKeyRing.getKeyById(keyPairId));
		}
	}

	@Test
	public void createAndExtendKeyFiles() throws Exception {
		Path workingDir = Files.createTempDirectory("keys");
		Path privateKeyRingFile = workingDir.resolve("privateKey");
		Path publicKeyRingFile = workingDir.resolve("publicKey");

		// assert that key files don't exist
		assertFalse(Files.exists(privateKeyRingFile));
		assertFalse(Files.exists(publicKeyRingFile));

		String firstKeyPairId = keyPairGenerator.createKeyPair("userId", "password", publicKeyRingFile, privateKeyRingFile);

		// assert that key files exist
		assertTrue(Files.exists(privateKeyRingFile));
		assertTrue(Files.exists(publicKeyRingFile));

		String secondKeyPairId = keyPairGenerator.createKeyPair("userId", "password", publicKeyRingFile, privateKeyRingFile);

		// assert that two distinct keys have been created
		assertTrue(firstKeyPairId != secondKeyPairId);

		// assert that both keys are contained in key files
		try (FileInputStream privateKeyIn = new FileInputStream(privateKeyRingFile.toFile())) {
			PrivateKeyRing privateKeyRing = new PrivateKeyRing(privateKeyIn, "password");
			assertNotNull(privateKeyRing.getKeyById(firstKeyPairId));
			assertNotNull(privateKeyRing.getKeyById(secondKeyPairId));
		}
		try (FileInputStream publicKeyIn = new FileInputStream(publicKeyRingFile.toFile())) {
			PublicKeyRing publicKeyRing = new PublicKeyRing(publicKeyIn);
			assertNotNull(publicKeyRing.getKeyById(firstKeyPairId));
			assertNotNull(publicKeyRing.getKeyById(secondKeyPairId));
		}
	}

	@Test
	public void createStreamBasedAndExtendFileBased() throws Exception {
		Path workingDir = Files.createTempDirectory("keys");
		Path privateKeyRingFile = workingDir.resolve("privateKey");
		Path publicKeyRingFile = workingDir.resolve("publicKey");

		// assert that key files don't exist
		assertFalse(Files.exists(privateKeyRingFile));
		assertFalse(Files.exists(publicKeyRingFile));

		String firstKeyPairId;
		try (FileOutputStream publicKeyOut = new FileOutputStream(publicKeyRingFile.toFile()); FileOutputStream privateKeyOut = new FileOutputStream(privateKeyRingFile.toFile())) {
			firstKeyPairId = keyPairGenerator.createKeyPair("userId", "password", publicKeyOut, privateKeyOut);
		}

		// assert that key files exist
		assertTrue(Files.exists(privateKeyRingFile));
		assertTrue(Files.exists(publicKeyRingFile));

		String secondKeyPairId = keyPairGenerator.createKeyPair("userId", "password", publicKeyRingFile, privateKeyRingFile);

		// assert that two distinct keys have been created
		assertTrue(firstKeyPairId != secondKeyPairId);

		// assert that both keys are contained in key files
		try (FileInputStream privateKeyIn = new FileInputStream(privateKeyRingFile.toFile())) {
			PrivateKeyRing privateKeyRing = new PrivateKeyRing(privateKeyIn, "password");
			assertNotNull(privateKeyRing.getKeyById(firstKeyPairId));
			assertNotNull(privateKeyRing.getKeyById(secondKeyPairId));
		}
		try (FileInputStream publicKeyIn = new FileInputStream(publicKeyRingFile.toFile())) {
			PublicKeyRing publicKeyRing = new PublicKeyRing(publicKeyIn);
			assertNotNull(publicKeyRing.getKeyById(firstKeyPairId));
			assertNotNull(publicKeyRing.getKeyById(secondKeyPairId));
		}
	}
}
