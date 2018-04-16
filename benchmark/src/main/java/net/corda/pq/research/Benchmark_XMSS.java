package net.corda.pq.research;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.openjdk.jmh.annotations.*;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Fork(1)
public class Benchmark_XMSS {

    @State(Scope.Benchmark)
    public static class Input {
        static XMSSBenchmarkContext context = null;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            if (context == null)
                context = new XMSSBenchmarkContext();
        }
    }

    @Benchmark
    public byte[] sign(Input input) throws Exception { return input.context.sign(); }

    @Benchmark
    public boolean verify(Input input) throws Exception { return input.context.verify(); }

    @Benchmark
    public KeyPair keyGeneration(Input input) { return input.context.makeKeyPair(); }
}

class XMSSBenchmarkContext extends AbstractBenchmarkContext {

    byte[] xmssPublicKey;
    byte[] xmssPrivateKey;
    static int H = 2;
    static XMSSParameters XMSSparameters = new XMSSParameters(H, new SHA256Digest());
    static XMSS xmss = new XMSS(XMSSparameters, new SecureRandom());
    static XMSS xmss_keygen = new XMSS(XMSSparameters, new SecureRandom());

    XMSSBenchmarkContext() throws Exception {
        xmss.generateKeys();
        xmssPrivateKey = xmss.exportPrivateKey();
        xmssPublicKey = xmss.exportPublicKey();
        super.init();
    }

    @Override
    public KeyPair makeKeyPair() {
        xmss_keygen.generateKeys();
        return null;
    }

    @Override
    public boolean doVerify(byte[] message, byte[] signature) throws Exception {
        return xmss.verifySignature(message, signature, xmssPublicKey);
    }

    @Override
    public byte[] doSign(byte[] message) throws Exception {
        xmss.importState(xmssPrivateKey, xmssPublicKey);
        return xmss.sign(message);
    }
}
