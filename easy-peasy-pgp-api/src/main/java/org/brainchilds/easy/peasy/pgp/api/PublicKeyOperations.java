package org.brainchilds.easy.peasy.pgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.brainchilds.easy.peasy.pgp.api.exceptions.PgpException;

public interface PublicKeyOperations {

	void encrypt(InputStream plaiIn, OutputStream encryptedOut) throws IOException, PgpException;

	void encrypt(long keyId, InputStream plaiIn, OutputStream encryptedOut) throws IOException, PgpException;

	boolean verify(InputStream signedIn, OutputStream plainOut) throws IOException, PgpException;

	boolean verify(InputStream plainIn, InputStream signatureIn) throws IOException, PgpException;
}
