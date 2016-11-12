package easy.peasy.pgp.bc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import easy.peasy.pgp.api.exceptions.PgpException;
import easy.peasy.pgp.api.keys.PgpKeyPairGenerator;

@Data
public class BcPgpKeyPairGenerator implements PgpKeyPairGenerator {
	private final int keySize;
	private final boolean asciiArmor;
	@Getter(AccessLevel.NONE)
	private final KeyPairGenerator keyPairGenerator;

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public BcPgpKeyPairGenerator() {
		this(2048, true);
	}

	public BcPgpKeyPairGenerator(int keySize, boolean asciiArmor) {
		this.keySize = keySize;
		this.asciiArmor = asciiArmor;
		try {
			this.keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			keyPairGenerator.initialize(keySize);
		} catch (NoSuchAlgorithmException e) {
			// every Java platform has to support RSA (1024, 2048)
			throw new IllegalStateException("RSA algorithm not supported", e);
		} catch (NoSuchProviderException e) {
			// bouncy castle provider was added in static init block
			throw new IllegalStateException(BouncyCastleProvider.PROVIDER_NAME + " provider not registered", e);
		}
	}

	@Override
	public long createKeyPair(String userId, String password, OutputStream publicKeyOut, OutputStream privateKeyOut) throws IOException, PgpException {
		try {
			PGPSecretKey pgpSecretKey = createSecretKey(userId, password);
			writeSecretKey(pgpSecretKey, privateKeyOut);

			PGPPublicKey pgpPublicKey = pgpSecretKey.getPublicKey();
			writePublicKey(pgpPublicKey, publicKeyOut);

			return pgpSecretKey.getKeyID();
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

	@Override
	public long createKeyPair(String userId, String password, Path publicKeyFile, Path privateKeyFile) throws IOException, PgpException {
		try {
			PGPSecretKey pgpSecretKey = createSecretKey(userId, password);
			if (Files.exists(privateKeyFile)) {
				PGPSecretKeyRingCollection secretKeyRingCollection = new PrivateKeyRing(new FileInputStream(privateKeyFile.toFile()), password).getKeyRingCollection();
				PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(pgpSecretKey.getEncoded(), new JcaKeyFingerprintCalculator());
				PGPSecretKeyRingCollection updatedSecretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection, secretKeyRing);

				writePrivateKeyRingCollection(updatedSecretKeyRingCollection, privateKeyFile);

			} else {
				createParentDirectories(privateKeyFile);
				writeSecretKey(pgpSecretKey, new FileOutputStream(privateKeyFile.toFile()));
			}

			PGPPublicKey pgpPublicKey = pgpSecretKey.getPublicKey();
			if (Files.exists(publicKeyFile)) {
				PGPPublicKeyRingCollection publicKeyRingCollection = new PublicKeyRing(new FileInputStream(publicKeyFile.toFile())).getKeyRingCollection();
				PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(pgpPublicKey.getEncoded(), new JcaKeyFingerprintCalculator());
				PGPPublicKeyRingCollection updatedPublicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, publicKeyRing);

				writePublicKeyRingCollection(updatedPublicKeyRingCollection, publicKeyFile);
			} else {
				createParentDirectories(publicKeyFile);
				writePublicKey(pgpPublicKey, new FileOutputStream(publicKeyFile.toFile()));
			}

			return pgpSecretKey.getKeyID();
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

	private PGPSecretKey createSecretKey(String userId, String password) throws PGPException {
		KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

		// only sha1 supported for keys
		PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKeyPair, new Date());
		PGPSecretKey pgpSecretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, pgpKeyPair, userId, digestCalculator, null, null, new JcaPGPContentSignerBuilder(
				pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, digestCalculator).setProvider(
				BouncyCastleProvider.PROVIDER_NAME).build(password.toCharArray()));
		return pgpSecretKey;
	}

	private void createParentDirectories(Path publicKeyRing) throws IOException {
		Path parent = publicKeyRing.getParent();
		if (!Files.exists(parent)) {
			Files.createDirectories(parent);
		}
	}

	private void writePublicKeyRingCollection(PGPPublicKeyRingCollection updatedPublicKeyRingCollection, Path publicKeyRingFile) throws FileNotFoundException, IOException {
		OutputStream publicKeyOut = new FileOutputStream(publicKeyRingFile.toFile());
		if (asciiArmor) {
			publicKeyOut = new ArmoredOutputStream(publicKeyOut);
		}
		updatedPublicKeyRingCollection.encode(publicKeyOut);
		publicKeyOut.close();
	}

	private void writePrivateKeyRingCollection(PGPSecretKeyRingCollection updatedSecretKeyRingCollection, Path privateKeyRingFile) throws FileNotFoundException, IOException {
		OutputStream privateKeyOut = new FileOutputStream(privateKeyRingFile.toFile());
		if (asciiArmor) {
			privateKeyOut = new ArmoredOutputStream(privateKeyOut);
		}
		updatedSecretKeyRingCollection.encode(privateKeyOut);
		privateKeyOut.close();
	}

	private void writePublicKey(PGPPublicKey pgpPublicKey, OutputStream publicKeyOut) throws IOException {
		if (asciiArmor) {
			publicKeyOut = new ArmoredOutputStream(publicKeyOut);
		}
		pgpPublicKey.encode(publicKeyOut);
		publicKeyOut.close();
	}

	private void writeSecretKey(PGPSecretKey pgpSecretKey, OutputStream privateKeyOut) throws IOException {
		if (asciiArmor) {
			privateKeyOut = new ArmoredOutputStream(privateKeyOut);
		}
		pgpSecretKey.encode(privateKeyOut);
		privateKeyOut.close();
	}

}
