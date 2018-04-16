package net.corda.pq.research;

import net.corda.core.crypto.Crypto;
import net.corda.core.crypto.SignatureScheme;

import java.security.KeyPair;

public class CryptoBenchmarkContext extends AbstractBenchmarkContext {

    public SignatureScheme scheme;

    CryptoBenchmarkContext(String schemeName) throws Exception {
        scheme = Crypto.findSignatureScheme(schemeName);
        super.init();
    }

    @Override
    public byte[] doSign(byte[] message) throws Exception {
        return Crypto.doSign(scheme, keyPair.getPrivate(), message);
    }

    @Override
    public boolean doVerify(byte[] message, byte[] signature) throws Exception {
        return Crypto.doVerify(scheme, keyPair.getPublic(), signature, message);
    }

    @Override
    public KeyPair makeKeyPair() {
        return Crypto.generateKeyPair(scheme);
    }
}
