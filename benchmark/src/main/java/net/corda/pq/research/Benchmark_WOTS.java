package net.corda.pq.research;

import javafx.util.Pair;
import net.corda.research.pq.SHA384;
import net.corda.research.pq.SHA384Debug;
import net.corda.research.pq.cordafts.CordaFTS;
import net.corda.research.pq.wots.PublicKey;
import net.corda.research.pq.wots.Signature;
import net.corda.research.pq.wots.WOTS;
import org.openjdk.jmh.annotations.*;

import java.security.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Fork(1)
@Threads(1)
public class Benchmark_WOTS {

    @State(Scope.Benchmark)
    public static class Input {

        @Param(value = {"1", "6"})
        int W;

        static WOTSBenchmarkContext context = null;

        @Setup(Level.Iteration)
        public void start() throws Exception {
            if (context == null)
                context = new WOTSBenchmarkContext(W);
            context.sha384Debug.setCounter(0);
        }

        @TearDown(Level.Iteration)
        public void teardown() {
            System.err.println("Counter: " + context.sha384Debug.getCounter());
        }
    }

    @Benchmark
    public boolean verify(Input input) throws Exception {
        return input.context.verify();
    }

    @Benchmark
    public KeyPair keygen(Input input) throws Exception {
        return input.context.makeKeyPair();
    }

    @Benchmark
    public Object keygenTest(Input input) throws Exception {
        return input.context.cordaFTS.generateKeyPairTest();
    }

    @Benchmark
    public byte[] sign(Input input) throws Exception {
        return input.context.sign();
    }
}

class WOTSBenchmarkContext extends AbstractBenchmarkContext {

    public WOTS cordaFTS;
    public SHA384Debug sha384Debug;
    public kotlin.Pair<
            net.corda.research.pq.wots.PublicKey,
            net.corda.research.pq.wots.PrivateKey> keyPair;

    WOTSBenchmarkContext(int W) throws Exception {
        sha384Debug = new SHA384Debug();
        cordaFTS = new WOTS(W, sha384Debug, sha384Debug, sha384Debug, new SecureRandom());
        keyPair = cordaFTS.generateKeyPair();
        super.init();
    }

    @Override
    public byte[] doSign(byte[] message) throws Exception {
        Signature sig = cordaFTS.sign(message, keyPair.component2());
        return Signature.Companion.serialize(sig);
    }

    @Override
    public boolean doVerify(byte[] message, byte[] signature) throws Exception {
       Signature s = Signature.Companion.deserialize(signature, 48);
       Signature s2 = cordaFTS.chainedHash(message, s.getRoots(), s.getChecksum(), true);
       return s2 != null;
    }

    public Signature deserialize() throws Exception {
        SignedMessage s = nextSignedMessage();
        return Signature.Companion.deserialize(s.signature, 48);
    }

    public PublicKey makePublicKey() throws Exception {
        SignedMessage s = nextSignedMessage();
        Signature sig = Signature.Companion.deserialize(s.signature, 48);
        return cordaFTS.makePublicKey(sig.getRoots(), sig.getChecksum());
    }

    public KeyPair makeKeyPair() {
        kotlin.Pair<
                net.corda.research.pq.wots.PublicKey,
                net.corda.research.pq.wots.PrivateKey> kp =
                cordaFTS.generateKeyPair();
        return new KeyPair(kp.component1(), kp.component2());
    }
}
