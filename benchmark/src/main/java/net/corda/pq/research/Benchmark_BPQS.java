package net.corda.pq.research;

import net.corda.research.pq.Hash;
import net.corda.research.pq.SHA256;
import net.corda.research.pq.SHA384;
import net.corda.research.pq.SHA512;
import org.openjdk.jmh.annotations.*;

import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Fork(1)
public class Benchmark_BPQS {

    @State(Scope.Benchmark)
    public static class Input {

        @Param(value = {"1", "6"})
        int W;

        @Param(value = {"5"})
        int maxRetry;

        @Param(value = {"0"})
        int retryId;

        @Param(value = {"SHA-256", "SHA-384", "SHA-512"})
        String hashName;

        static BPQSBenchmarkContext context = null;

        @Setup(Level.Invocation)
        public void start() throws Exception {
            if (context == null) {
                Hash H;
                if (hashName.equals("SHA-256")) {
                    H = new SHA256();
                } else if (hashName.equals("SHA-384")) {
                    H = new SHA384();
                } else if (hashName.equals("SHA-512")) {
                    H = new SHA512();
                } else {
                    throw new IllegalArgumentException("Unrecognized hash " + hashName);
                }

                context = new BPQSBenchmarkContext(W, maxRetry, retryId, H);
            }
        }
    }

    @Benchmark
    public byte[] sign(Input input) throws Exception { return input.context.sign(); }

    @Benchmark
    public boolean verify(Input input) throws Exception { return input.context.verify(); }

   @Benchmark
    public KeyPair keyGeneration(Input input) { return input.context.makeKeyPair(); }
}
