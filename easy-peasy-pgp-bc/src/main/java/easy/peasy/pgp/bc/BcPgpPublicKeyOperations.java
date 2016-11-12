package easy.peasy.pgp.bc;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import easy.peasy.pgp.api.PgpPublicKeyOperations;
import easy.peasy.pgp.api.exceptions.PgpException;

@Data
@AllArgsConstructor
public class BcPgpPublicKeyOperations implements PgpPublicKeyOperations {

	private final PublicKeyRing keyRing;
	private final boolean asciiArmor;
	private final boolean integrityCheck;
	private final int bufferSize;
	private final boolean zipCompression;

	public BcPgpPublicKeyOperations(PublicKeyRing keyRing) {
		this.keyRing = keyRing;
		this.asciiArmor = true;
		this.integrityCheck = true;
		this.bufferSize = 64;
		this.zipCompression = true;
	}

	@Override
	public void encrypt(InputStream plainIn, OutputStream encryptedOut) throws IOException, PgpException {
		doEncrypt(null, plainIn, encryptedOut);
	}

	@Override
	public void encrypt(long keyId, InputStream plainIn, OutputStream encryptedOut) throws IOException, PgpException {
		doEncrypt(Long.valueOf(keyId), plainIn, encryptedOut);
	}

	private void doEncrypt(Long keyId, InputStream plainIn, OutputStream encryptedOut) throws IOException, PgpException {
		try {
			if (asciiArmor) {
				encryptedOut = new ArmoredOutputStream(encryptedOut);
			}
			PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
					.setWithIntegrityPacket(integrityCheck).setSecureRandom(new SecureRandom()).setProvider(BouncyCastleProvider.PROVIDER_NAME));
			PGPPublicKey publicKey = keyId != null ? keyRing.getKeyById(keyId) : keyRing.getFirstKey();
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));

			OutputStream encryptionStream = encryptedDataGenerator.open(encryptedOut, new byte[bufferSize]);
			PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
			if (zipCompression) {
				encryptionStream = compressedDataGenerator.open(encryptionStream);
			}
			PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
			OutputStream literalDataStream = literalDataGenerator.open(encryptionStream, PGPLiteralData.BINARY, "unknown", new Date(), new byte[bufferSize]);

			Streams.pipeAll(plainIn, literalDataStream);
			literalDataGenerator.close();
			compressedDataGenerator.close();
			encryptedDataGenerator.close();

			encryptedOut.close();
			plainIn.close();
		} catch (PGPException e) {
			throw new PgpException("Failed to encrypt data", e);
		}
	}

	@Override
	public boolean verify(InputStream signedIn, OutputStream plainOut) throws IOException, PgpException {
		try {
			signedIn = PGPUtil.getDecoderStream(signedIn);

			JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(signedIn);
			Object pgpObject = objectFactory.nextObject();

			if (pgpObject instanceof PGPCompressedData) {
				PGPCompressedData compressedData = (PGPCompressedData) pgpObject;
				objectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
				pgpObject = objectFactory.nextObject();
			}

			PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) pgpObject;
			PGPOnePassSignature signature = onePassSignatureList.get(0);
			PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
			InputStream literalDataIn = literalData.getInputStream();
			PGPPublicKey publicKey = keyRing.getKeyById(signature.getKeyID());
			signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BouncyCastleProvider.PROVIDER_NAME), publicKey);

			if (!(literalDataIn instanceof BufferedInputStream)) {
				literalDataIn = new BufferedInputStream(literalDataIn, bufferSize);
			}

			readSignedData(plainOut, signature, literalDataIn);

			plainOut.close();
			PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
			return signature.verify(signatureList.get(0));
		} catch (PGPException e) {
			throw new PgpException("Failed to verify signature", e);
		}
	}

	private void readSignedData(OutputStream plainOut, PGPOnePassSignature signature, InputStream literalDataIn) throws IOException {
		int nextByte;
		while ((nextByte = literalDataIn.read()) >= 0) {
			signature.update((byte) nextByte);
			plainOut.write(nextByte);
		}
	}

}
