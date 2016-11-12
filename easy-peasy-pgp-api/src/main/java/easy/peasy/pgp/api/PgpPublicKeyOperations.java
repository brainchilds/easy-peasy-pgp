package easy.peasy.pgp.api;

import easy.peasy.pgp.api.encryption.PgpEncryptor;
import easy.peasy.pgp.api.signature.PgpVerifier;

public interface PgpPublicKeyOperations extends PgpEncryptor, PgpVerifier {

}
