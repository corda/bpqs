package net.corda.pq.research;

import net.corda.research.pq.Hash;
import net.corda.research.pq.SHA256;
import net.corda.research.pq.SHA384;
import net.corda.research.pq.SHA512;
import net.corda.research.pq.cordafts.CordaFTS;
import net.corda.research.pq.wots.WOTS;

import java.security.KeyPair;
import java.security.SecureRandom;

public class BPQSBenchmarkContext extends AbstractBenchmarkContext {

    public CordaFTS cordaFTS;
    public KeyPair keyPair;
    int maxFallback;
    int retryId;

    BPQSBenchmarkContext(int W, int maxFallback, int retryId, Hash H) throws Exception {
        WOTS wots = new WOTS(W, H, H, H, new SecureRandom());
        cordaFTS = new CordaFTS(wots);
        keyPair = cordaFTS.generateKeyPair(maxFallback);
        this.maxFallback = maxFallback;
        this.retryId = retryId;
        super.init();
    }

    @Override
    public byte[] doSign(byte[] message) throws Exception {
        return cordaFTS.sign(message, keyPair.getPrivate(), retryId);
    }

    @Override
    public boolean doVerify(byte[] message, byte[] signature) throws Exception {
        cordaFTS.verify(message, keyPair.getPublic(), signature);
        return true;
    }

    @Override
    public KeyPair makeKeyPair() {
        return cordaFTS.generateKeyPair(maxFallback);
    }
}
