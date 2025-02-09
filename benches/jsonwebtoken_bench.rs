use ciftl::crypter::StringCrypterTrait;
use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fn generate_claim() -> Claims {
    Claims {
        sub: "1234567890".to_string(),
        company: "example".to_string(),
        exp: 1516239022,
    }
}

fn claims_to_json(claims: &Claims) -> String {
    serde_json::to_string(claims).unwrap()
}

fn generate_jwt_token() -> String {
    let my_claims = generate_claim();
    let token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )
    .unwrap();
    token
}

fn generate_ciftl_token() -> String {
    let claim = generate_claim();
    let json_string = claims_to_json(&claim);
    let crypter =
        ciftl::crypter::StringCrypter::<ciftl::crypter::chacha20::ChaCha20CipherAlgorithm>::default(
        );
    crypter.encrypt(&json_string, "secret").unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_generation");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10000);
    group.bench_function("generate_jwt_token", |b| b.iter(|| generate_jwt_token()));

    group.bench_function("generate_ciftl_token", |b| {
        b.iter(|| generate_ciftl_token())
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
