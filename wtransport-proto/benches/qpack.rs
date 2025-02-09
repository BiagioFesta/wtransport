use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::Criterion;
use rand::thread_rng;
use rand::Rng;
use wtransport_proto::qpack::Decoder;
use wtransport_proto::qpack::Encoder;

fn generate_random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(len)
        .map(char::from)
        .collect::<String>()
}

fn bench_qpack(c: &mut Criterion) {
    c.bench_function("encoder", |b| {
        b.iter_batched_ref(
            || {
                let authority = generate_random_string(150);
                let path = generate_random_string(150);

                vec![
                    (":method".to_string(), "CONNECT".to_string()),
                    (":scheme".to_string(), "https".to_string()),
                    (":protocol".to_string(), "webtransport".to_string()),
                    (":authority".to_string(), authority),
                    (":path".to_string(), path),
                ]
            },
            |headers| Encoder::encode(headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("decoder", |b| {
        b.iter_batched(
            || {
                let authority = generate_random_string(150);
                let path = generate_random_string(150);

                Encoder::encode([
                    (":method", "CONNECT"),
                    (":scheme", "https"),
                    (":protocol", "webtransport"),
                    (":authority", &authority),
                    (":path", &path),
                ])
            },
            Decoder::decode,
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(qpack, bench_qpack);
criterion_main!(qpack);
