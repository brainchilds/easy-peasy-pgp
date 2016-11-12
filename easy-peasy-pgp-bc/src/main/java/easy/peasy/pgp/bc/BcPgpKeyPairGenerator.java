package easy.peasy.pgp.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

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

@AllArgsConstructor
@NoArgsConstructor
public class BcPgpKeyPairGenerator implements PgpKeyPairGenerator {
	private int keySize = 2048;
	private boolean asciiArmor = true;

	public long createKeyPair(String userId, OutputStream publicKeyOut, OutputStream privateKeyOut, String privateKeyPassword) throws IOException, NoSuchProviderException,
			NoSuchAlgorithmException, PgpException {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			keyPairGenerator.initialize(keySize);
			KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

			// only sha1 supported for keys
			PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
			PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKeyPair, new Date());
			PGPSecretKey pgpSecretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, pgpKeyPair, userId, digestCalculator, null, null, new JcaPGPContentSignerBuilder(
					pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, digestCalculator).setProvider(
					BouncyCastleProvider.PROVIDER_NAME).build(privateKeyPassword.toCharArray()));

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
