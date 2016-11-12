package easy.peasy.pgp.bc;

import java.io.IOException;
import java.io.OutputStream;
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
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
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

	public long createKeyPair(String userId, OutputStream publicKeyOut, OutputStream privateKeyOut, String password) throws IOException, PgpException {
		try {
			KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

			// only sha1 supported for keys
			PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
			PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKeyPair, new Date());
			PGPSecretKey pgpSecretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, pgpKeyPair, userId, digestCalculator, null, null, new JcaPGPContentSignerBuilder(
					pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, digestCalculator).setProvider(
					BouncyCastleProvider.PROVIDER_NAME).build(password.toCharArray()));

			if (asciiArmor) {
				privateKeyOut = new ArmoredOutputStream(privateKeyOut);
				publicKeyOut = new ArmoredOutputStream(publicKeyOut);
			}
			pgpSecretKey.encode(privateKeyOut);
			privateKeyOut.close();

			PGPPublicKey pgpPublicKey = pgpSecretKey.getPublicKey();
			pgpPublicKey.encode(publicKeyOut);
			publicKeyOut.close();

			return pgpKeyPair.getKeyID();
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

}
