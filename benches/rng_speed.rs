use criterion::{criterion_group, criterion_main, Criterion};
use userspace_random::random256;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("random256", |b| b.iter(|| random256()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
