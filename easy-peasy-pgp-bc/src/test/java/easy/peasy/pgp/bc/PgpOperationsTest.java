package easy.peasy.pgp.bc;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import easy.peasy.pgp.api.PgpPrivateKeyOperations;
import easy.peasy.pgp.api.PgpPublicKeyOperations;

public class PgpOperationsTest {

	@BeforeClass
	public static void addBcSecurityProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setup() throws Exception {
		BcPgpKeyPairGenerator keyPairFactory = new BcPgpKeyPairGenerator();
		ByteArrayOutputStream publicKeyOut = new ByteArrayOutputStream();
		ByteArrayOutputStream privateKeyOut = new ByteArrayOutputStream();
		final String password = "password";
		keyPairFactory.createKeyPair("user", password, publicKeyOut, privateKeyOut);

		publicKeyOperations = new BcPgpPublicKeyOperations(new PublicKeyRing(new ByteArrayInputStream(publicKeyOut.toByteArray())));
		privateKeyOperations = new BcPgpPrivateKeyOperations(new PrivateKeyRing(new ByteArrayInputStream(privateKeyOut.toByteArray()), password));
	}

	private PgpPublicKeyOperations publicKeyOperations;
	private PgpPrivateKeyOperations privateKeyOperations;

	@Test
	public void encryptAndDecrypt() throws Exception {
		byte[] samplePayload = getTestPayload();

		ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
		publicKeyOperations.encrypt(new ByteArrayInputStream(samplePayload), encryptedOut);

		ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
		privateKeyOperations.decrypt(new ByteArrayInputStream(encryptedOut.toByteArray()), decryptedOut);

		assertTrue(Arrays.equals(samplePayload, decryptedOut.toByteArray()));
	}

	@Test
	public void signAndVerify() throws Exception {
		byte[] samplePayload = getTestPayload();

		ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
		privateKeyOperations.sign(new ByteArrayInputStream(samplePayload), signedOut);

		ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
		boolean signatureVerified = publicKeyOperations.verify(new ByteArrayInputStream(signedOut.toByteArray()), plainOut);

		assertTrue(signatureVerified);
		assertTrue(Arrays.equals(samplePayload, plainOut.toByteArray()));
	}

	private static byte[] getTestPayload() throws IOException {
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			InputStream payloadStream = PgpOperationsTest.class.getResourceAsStream("sample-payload.txt");
			Streams.pipeAll(payloadStream, buffer);
			return buffer.toByteArray();
		}
	}

}
