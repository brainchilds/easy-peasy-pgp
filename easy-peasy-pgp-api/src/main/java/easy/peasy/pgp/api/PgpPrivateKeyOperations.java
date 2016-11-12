package easy.peasy.pgp.api;

import easy.peasy.pgp.api.encryption.PgpDecryptor;
import easy.peasy.pgp.api.signature.PgpSigner;

public interface PgpPrivateKeyOperations extends PgpDecryptor, PgpSigner {

}
