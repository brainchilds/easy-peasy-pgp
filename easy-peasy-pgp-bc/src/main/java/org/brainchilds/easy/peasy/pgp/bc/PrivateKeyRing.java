package org.brainchilds.easy.peasy.pgp.bc;

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

import easy.peasy.pgp.api.exceptions.PgpException;

@Data
public class PrivateKeyRing {
	private final PGPSecretKeyRingCollection keyRingCollection;
	@Getter(AccessLevel.NONE)
	private final char[] password;

	public PrivateKeyRing(InputStream privateKeyIn, String password) throws IOException, PgpException {
		try {
			this.keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn), new JcaKeyFingerprintCalculator());
			this.password = password.toCharArray();
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

	public PrivateKeyRing(PGPSecretKeyRingCollection keyRingCollection, String password) {
		this.keyRingCollection = keyRingCollection;
		this.password = password.toCharArray();
	}

	public PGPSecretKey getFirstSecretKey() throws PgpException {
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
		throw new PgpException("Given key ring does not contain any private key");
	}

	public PGPSecretKey getSecretKeyById(long keyId) throws PgpException {
		try {
			return keyRingCollection.getSecretKey(keyId);
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

	public PGPPrivateKey getFirstPrivateKey() throws PgpException {
		return extractPrivateKey(getFirstSecretKey());
	}

	public PGPPrivateKey getKeyById(long keyId) throws PgpException {
		try {
			PGPSecretKey secretKey = keyRingCollection.getSecretKey(keyId);
			if (secretKey == null) {
				return null;
			}
			return extractPrivateKey(secretKey);
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

	public PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey) throws PgpException {
		try {
			return secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password));
		} catch (PGPException e) {
			throw new PgpException(e);
		}
	}

}
