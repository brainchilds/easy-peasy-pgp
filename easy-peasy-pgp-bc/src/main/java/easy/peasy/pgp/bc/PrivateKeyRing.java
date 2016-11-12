package easy.peasy.pgp.bc;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

@Data
public class PrivateKeyRing {
	private final PGPSecretKeyRingCollection keyRingCollection;
	@Getter(AccessLevel.NONE)
	private final char[] password;

	public PrivateKeyRing(InputStream privateKeyIn, String password) throws IOException, PGPException {
		this.keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn), new JcaKeyFingerprintCalculator());
		this.password = password.toCharArray();
	}

	public PrivateKeyRing(PGPSecretKeyRingCollection keyRingCollection, String password) {
		this.keyRingCollection = keyRingCollection;
		this.password = password.toCharArray();
	}

	public PGPSecretKey getFirstSecretKey() throws PGPException {
		Iterator<PGPSecretKeyRing> keyRings = keyRingCollection.getKeyRings();
		while (keyRings.hasNext()) {
			PGPSecretKeyRing keyRing = keyRings.next();
			Iterator<PGPSecretKey> secretKeys = keyRing.getSecretKeys();
			while (secretKeys.hasNext()) {
				PGPSecretKey secretKey = secretKeys.next();
				if (secretKey.isMasterKey()) {
					return secretKey;
				}
			}
		}
		throw new PGPException("Given key ring does not contain any private key");
	}

	public PGPSecretKey getSecretKeyById(long keyId) throws PGPException {
		return keyRingCollection.getSecretKey(keyId);
	}

	public PGPPrivateKey getFirstPrivateKey() throws PGPException {
		return getPrivateKey(getFirstSecretKey());
	}

	public PGPPrivateKey getKeyById(long keyId) throws PGPException {
		PGPSecretKey secretKey = keyRingCollection.getSecretKey(keyId);
		if(secretKey==null){
			return null;
		}
		return getPrivateKey(secretKey);
	}

	public PGPPrivateKey getPrivateKey(PGPSecretKey secretKey) throws PGPException {
		return secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password));
	}

}
