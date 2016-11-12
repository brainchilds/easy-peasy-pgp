package easy.peasy.pgp.bc;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import lombok.Data;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

@Data
public class PublicKeyRing {
	private final PGPPublicKeyRingCollection keyRingCollection;

	public PublicKeyRing(PGPPublicKeyRingCollection keyRingCollection) {
		this.keyRingCollection = keyRingCollection;
	}

	public PublicKeyRing(InputStream publicKeyIn) throws IOException, PGPException {
		this.keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());
	}

	public PGPPublicKey getFirstKey() throws PGPException {
		Iterator<PGPPublicKeyRing> keyRingIterator = keyRingCollection.getKeyRings();
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = keyRingIterator.next();
			Iterator<PGPPublicKey> keyIterator = keyRing.getPublicKeys();
			while (keyIterator.hasNext()) {
				PGPPublicKey key = keyIterator.next();
				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}
		throw new PGPException("Given key ring does not contain any public encryption key");
	}

	public PGPPublicKey getKeyById(long keyId) throws PGPException {
		return keyRingCollection.getPublicKey(keyId);
	}

}
