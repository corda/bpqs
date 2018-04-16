package net.corda.pq.research;

import net.corda.core.crypto.Crypto;
import net.corda.core.crypto.SignatureScheme;
import org.openjdk.jmh.annotations.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Random;
import java.util.concurrent.TimeUnit;

class SignedMessage {
    byte[] message;
    byte[] signature;
    static int ID = 0;

    SignedMessage(byte[] message_, byte[] signature_) {
        message = message_;
        signature = signature_;
    }
}

public abstract class AbstractBenchmarkContext {

    static final int BATCH_SIZE = 5;
    static final int MSG_LEN = 512;
    static final int SEED = 1000;

    public KeyPair keyPair = null;
    public byte[][] signatures;
    public byte[][] msgs;
    public int SIGN_CNT = 0;
    public int VERIFY_CNT = 0;

    /*
     * Pregenerate random messages and sign them
     */
    protected void init() throws Exception {
        msgs = new byte[BATCH_SIZE][];
        Random random = new Random(SEED);
        for (int id = 0; id < BATCH_SIZE; ++id) {
            msgs[id] = new byte[MSG_LEN];
            random.nextBytes(msgs[id]);
        }

        keyPair = makeKeyPair();
        signatures = batchSign(msgs);
    }

    /*************************************************************************************/
    protected SignedMessage nextSignedMessage() {
        int ID = (SignedMessage.ID++) % BATCH_SIZE;
        SignedMessage result = new SignedMessage(msgs[ID], signatures[ID]);
        return result;
    }

    /*************************************************************************************/

    public byte[] sign() throws Exception {
        return doSign(nextSignedMessage().message);
    }

    /*************************************************************************************/

    public boolean verify() throws Exception {
        SignedMessage signedMessage = nextSignedMessage();
        return doVerify(signedMessage.message, signedMessage.signature);
    }

    /*************************************************************************************/

    public byte[][] batchSign(byte[][] clearData) throws Exception {
        byte[][] signed = new byte[clearData.length][];
        for(int id = 0; id < clearData.length; ++id) {
            signed[id] = doSign(clearData[id]);
        }
        return signed;
    }

    /*************************************************************************************/

    public abstract byte[] doSign(byte[] message) throws Exception;
    public abstract boolean doVerify(byte[] message, byte[] signature) throws Exception;
    public abstract KeyPair makeKeyPair();
}
