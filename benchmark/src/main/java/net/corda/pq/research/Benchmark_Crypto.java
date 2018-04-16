package net.corda.pq.research;

import net.corda.core.crypto.Crypto;
import org.openjdk.jmh.annotations.*;

import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Fork(1)
public class Benchmark_Crypto {

    @State(Scope.Benchmark)
    public static class Input {

        @Param(value = {
                "RSA_SHA256",
                "EDDSA_ED25519_SHA512",
                "ECDSA_SECP256R1_SHA256",
                "ECDSA_SECP256K1_SHA256",
                "SPHINCS-256_SHA512"})
        String schemeName;

        static CryptoBenchmarkContext context = null;

        @Setup(Level.Invocation)
        public void start() throws Exception {
            if (context == null)
                context = new CryptoBenchmarkContext(schemeName);
        }
    }

    @Benchmark
    public byte[] sign(Input input) throws Exception { return input.context.sign(); }

    @Benchmark
    public boolean verify(Input input) throws Exception { return input.context.verify(); }

    @Benchmark
    public KeyPair keyGeneration(Input input) { return input.context.makeKeyPair(); }
}
