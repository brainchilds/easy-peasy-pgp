package org.brainchilds.easy.peasy.pgp.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Iterator;

import lombok.Builder;
import lombok.Data;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.brainchilds.easy.peasy.pgp.api.PrivateKeyOperations;
import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

@Data
@Builder
public class BcPgpPrivateKeyOperations implements PrivateKeyOperations {

	private final PrivateKeyRing keyRing;
	private final Boolean asciiArmor;
	private final Boolean detachedSignature;
	private final Integer bufferSize;

	public BcPgpPrivateKeyOperations(PrivateKeyRing keyRing) {
		this(keyRing, null, null, null);
	}

	public BcPgpPrivateKeyOperations(PrivateKeyRing keyRing, Boolean asciiArmor, Boolean detachedSignature, Integer bufferSize) {
		this.keyRing = keyRing;
		this.asciiArmor = asciiArmor != null ? asciiArmor : Boolean.TRUE;
		this.detachedSignature = detachedSignature != null ? detachedSignature : Boolean.FALSE;
		this.bufferSize = bufferSize != null ? bufferSize : Integer.valueOf(64);
	}

	@Override
	@SuppressWarnings({ "unchecked" })
	public void decrypt(InputStream encryptedIn, OutputStream decryptedOut) throws IOException, PgpException {
		try {
			encryptedIn = StreamWrapperUtils.wrap(encryptedIn, true);
			decryptedOut = StreamWrapperUtils.wrap(decryptedOut, false);

			JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(encryptedIn);
			PGPEncryptedDataList encryptedDataList = extractEncryptedDataList(objectFactory);
			Iterator<PGPPublicKeyEncryptedData> encryptedObjectsIterator = encryptedDataList.getEncryptedDataObjects();
			PGPPrivateKey privateKey = null;
			PGPPublicKeyEncryptedData encryptedData = null;

			while (privateKey == null && encryptedObjectsIterator.hasNext()) {
				encryptedData = encryptedObjectsIterator.next();
				privateKey = keyRing.getKeyById(encryptedData.getKeyID());
			}

			if (privateKey == null) {
				throw new PGPException("No matching private key found");
			}

			InputStream decryptedDataInputStream = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
					privateKey));
			JcaPGPObjectFactory decryptedObjectFactory = new JcaPGPObjectFactory(decryptedDataInputStream);

			PGPLiteralData literalData = extractLiteralData(decryptedObjectFactory);
			InputStream literalDataStream = literalData.getInputStream();

			Streams.pipeAll(literalDataStream, decryptedOut);
			literalDataStream.close();
			decryptedOut.close();

			if (encryptedData.isIntegrityProtected()) {
				if (!encryptedData.verify()) {
					throw new PGPException("Data integrity check failed");
				}
			}
		} catch (PGPException e) {
			throw new PgpException("Failed to decrypt data", e);
		}
	}

	@Override
	public void sign(InputStream plainIn, OutputStream signedOut) throws IOException, PgpException {
		doSign(null, plainIn, signedOut);
	}

	@Override
	public void sign(String keyId, InputStream plainIn, OutputStream signedOut) throws IOException, PgpException {
		doSign(keyId, plainIn, signedOut);
	}

	@SuppressWarnings("unchecked")
	private void doSign(String keyId, InputStream plainIn, OutputStream signedOut) throws IOException, PgpException {
		try {
			plainIn = StreamWrapperUtils.wrap(plainIn, false);
			signedOut = StreamWrapperUtils.wrap(signedOut, this.asciiArmor);

			PGPSecretKey secretKey = keyId != null ? keyRing.getSecretKeyById(keyId) : keyRing.getFirstSecretKey();
			PGPPrivateKey privateKey = keyRing.extractPrivateKey(secretKey);

			PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256).setProvider(BouncyCastleProvider.PROVIDER_NAME));
			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

			Iterator<String> userIdIterator = secretKey.getPublicKey().getUserIDs();
			if (userIdIterator.hasNext()) {
				String userId = userIdIterator.next();
				PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
				signatureSubpacketGenerator.setSignerUserID(false, userId);
				signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
			}

			if (detachedSignature) {
				BCPGOutputStream bcOut = new BCPGOutputStream(signedOut);
				writeSignature(plainIn, signatureGenerator);

				signatureGenerator.generate().encode(bcOut);
				signedOut.close();
			} else {
				PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
				BCPGOutputStream bcOut = new BCPGOutputStream(compressedDataGenerator.open(signedOut));
				signatureGenerator.generateOnePassVersion(false).encode(bcOut);
				PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
				OutputStream literalDataGeneratorOut = literalDataGenerator.open(bcOut, PGPLiteralData.BINARY, "unknown", new Date(), new byte[bufferSize]);

				writeSignedData(plainIn, signatureGenerator, literalDataGeneratorOut);

				literalDataGenerator.close();
				signatureGenerator.generate().encode(bcOut);
				compressedDataGenerator.close();
				signedOut.close();
			}

		} catch (PGPException e) {
			throw new PgpException("Failed to sign data", e);
		}

	}

	private void writeSignedData(InputStream plainIn, PGPSignatureGenerator signatureGenerator, OutputStream literalDataGeneratorOut) throws IOException {
		int nextByte;
		while ((nextByte = plainIn.read()) >= 0) {
			literalDataGeneratorOut.write(nextByte);
			signatureGenerator.update((byte) nextByte);
		}
	}

	private void writeSignature(InputStream plainIn, PGPSignatureGenerator signatureGenerator) throws IOException {
		int nextByte;
		while ((nextByte = plainIn.read()) >= 0) {
			signatureGenerator.update((byte) nextByte);
		}
	}

	private PGPLiteralData extractLiteralData(JcaPGPObjectFactory decryptedObjectFactory) throws IOException, PGPException {
		Object decryptedObject = decryptedObjectFactory.nextObject();

		if (decryptedObject instanceof PGPCompressedData) {
			PGPCompressedData compressedData = (PGPCompressedData) decryptedObject;
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
			decryptedObject = pgpFact.nextObject();
		}

		if (decryptedObject instanceof PGPLiteralData) {
			return (PGPLiteralData) decryptedObject;
		} else if (decryptedObject instanceof PGPOnePassSignatureList) {
			throw new PGPException("Given payload is not encrypted but signed");
		} else {
			throw new PGPException("Given payload does not contain encrypted data");
		}
	}

	@SuppressWarnings("rawtypes")
	private PGPEncryptedDataList extractEncryptedDataList(JcaPGPObjectFactory objectFactory) throws PGPException {
		Iterator iterator = objectFactory.iterator();
		while (iterator.hasNext()) {
			Object next = iterator.next();
			if (next instanceof PGPEncryptedDataList) {
				return (PGPEncryptedDataList) next;
			}
		}
		throw new PGPException("Given payload does not contain encrypted data");
	}

}
