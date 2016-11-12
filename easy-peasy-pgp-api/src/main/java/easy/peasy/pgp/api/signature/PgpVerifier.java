package easy.peasy.pgp.api.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import easy.peasy.pgp.api.exceptions.PgpException;

public interface PgpVerifier {

	boolean verify(InputStream signedIn, OutputStream plainOut) throws IOException, PgpException;

	boolean verify(InputStream plainIn, InputStream signatureIn) throws IOException, PgpException;

}
