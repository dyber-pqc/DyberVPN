//! DyberVPN Cryptographic Benchmarks
//!
//! Run with: cargo bench -p dybervpn-protocol

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dybervpn_protocol::select_backend;

fn bench_mlkem_keygen(c: &mut Criterion) {
    let backend = select_backend();

    c.bench_function("mlkem_768_keygen", |b| {
        b.iter(|| {
            let _ = black_box(backend.mlkem_keygen().unwrap());
        })
    });
}

fn bench_mlkem_encaps(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, _sk) = backend.mlkem_keygen().unwrap();

    c.bench_function("mlkem_768_encaps", |b| {
        b.iter(|| {
            let _ = black_box(backend.mlkem_encaps(&pk).unwrap());
        })
    });
}

fn bench_mlkem_decaps(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.mlkem_keygen().unwrap();
    let (ct, _ss) = backend.mlkem_encaps(&pk).unwrap();

    c.bench_function("mlkem_768_decaps", |b| {
        b.iter(|| {
            let _ = black_box(backend.mlkem_decaps(&sk, &ct).unwrap());
        })
    });
}

fn bench_x25519_keygen(c: &mut Criterion) {
    let backend = select_backend();

    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let _ = black_box(backend.x25519_keygen().unwrap());
        })
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.x25519_keygen().unwrap();

    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| {
            let _ = black_box(backend.x25519_diffie_hellman(&sk, &pk).unwrap());
        })
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let backend = select_backend();
    let (_pk, sk) = backend.ed25519_keygen().unwrap();
    let message = b"DyberVPN benchmark message for signing";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let _ = black_box(backend.ed25519_sign(&sk, message).unwrap());
        })
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.ed25519_keygen().unwrap();
    let message = b"DyberVPN benchmark message for signing";
    let signature = backend.ed25519_sign(&sk, message).unwrap();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let _ = black_box(backend.ed25519_verify(&pk, message, &signature).unwrap());
        })
    });
}

fn bench_hybrid_handshake(c: &mut Criterion) {
    let backend = select_backend();

    c.bench_function("hybrid_handshake_initiator", |b| {
        b.iter(|| {
            // Initiator side: keygen for both X25519 and ML-KEM
            let (x_pk, x_sk) = backend.x25519_keygen().unwrap();
            let (m_pk, _m_sk) = backend.mlkem_keygen().unwrap();
            black_box((x_pk, x_sk, m_pk))
        })
    });

    c.bench_function("hybrid_handshake_responder", |b| {
        // Pre-generate initiator keys
        let (x_pk, _x_sk) = backend.x25519_keygen().unwrap();
        let (m_pk, _m_sk) = backend.mlkem_keygen().unwrap();

        b.iter(|| {
            // Responder side: keygen + DH + encaps
            let (r_x_pk, r_x_sk) = backend.x25519_keygen().unwrap();
            let x_ss = backend.x25519_diffie_hellman(&r_x_sk, &x_pk).unwrap();
            let (ct, m_ss) = backend.mlkem_encaps(&m_pk).unwrap();
            black_box((r_x_pk, x_ss, ct, m_ss))
        })
    });

    c.bench_function("hybrid_handshake_full", |b| {
        b.iter(|| {
            // Full handshake simulation
            // Initiator
            let (i_x_pk, i_x_sk) = backend.x25519_keygen().unwrap();
            let (i_m_pk, i_m_sk) = backend.mlkem_keygen().unwrap();

            // Responder
            let (r_x_pk, r_x_sk) = backend.x25519_keygen().unwrap();
            let r_x_ss = backend.x25519_diffie_hellman(&r_x_sk, &i_x_pk).unwrap();
            let (ct, r_m_ss) = backend.mlkem_encaps(&i_m_pk).unwrap();

            // Initiator completes
            let i_x_ss = backend.x25519_diffie_hellman(&i_x_sk, &r_x_pk).unwrap();
            let i_m_ss = backend.mlkem_decaps(&i_m_sk, &ct).unwrap();

            black_box((i_x_ss, i_m_ss, r_x_ss, r_m_ss))
        })
    });
}

fn bench_hkdf(c: &mut Criterion) {
    let backend = select_backend();
    let ikm = [0u8; 32];
    let salt = b"DyberVPN-benchmark-salt";
    let info = b"DyberVPN benchmark";

    c.bench_function("hkdf_sha256_32bytes", |b| {
        b.iter(|| {
            let mut okm = [0u8; 32];
            backend.hkdf_sha256(salt, &ikm, info, &mut okm).unwrap();
            black_box(okm)
        })
    });

    c.bench_function("hkdf_sha256_64bytes", |b| {
        b.iter(|| {
            let mut okm = [0u8; 64];
            backend.hkdf_sha256(salt, &ikm, info, &mut okm).unwrap();
            black_box(okm)
        })
    });
}

criterion_group!(
    benches,
    bench_mlkem_keygen,
    bench_mlkem_encaps,
    bench_mlkem_decaps,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_hybrid_handshake,
    bench_hkdf,
);

criterion_main!(benches);
