## 使用ciftl-rs实现类似jwt功能的性能基准测试

在现代Web开发中，JSON Web Token（JWT）是一种广泛使用的身份验证机制。它不仅用于用户认证，还可以在不同系统之间传递信息。然而，在某些场景下，我们可能需要使用自定义加密方式来实现类似的令牌功能。本文将介绍如何使用`ciftl-rs`库创建一个类似于JWT的功能，并通过性能基准测试对比两者的性能差异。

### 1. 定义数据结构

为了模拟真实的使用场景，我们需要定义一个包含用户信息的数据结构。这里以简单的`Claims`为例：

```rust
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}
```

### 2. 实现JWT生成函数

接下来实现标准的JWT生成逻辑：

```rust
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
```

### 3. 实现基于ciftl-rs的令牌生成

同样地，我们也为`ciftl-rs`实现一个令牌生成方法：

```rust
fn generate_ciftl_token() -> String {
    let claim = generate_claim();
    let json_string = claims_to_json(&claim);
    let crypter =
        ciftl::crypter::StringCrypter::<ciftl::crypter::chacha20::ChaCha20CipherAlgorithm>::default();
    crypter.encrypt(&json_string, "secret").unwrap()
}
```

### 4. 性能基准测试

为了比较两种方式之间的性能差异，我们可以使用`criterion`库来进行基准测试。以下是具体的实现代码：

```rust
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
```

### 5. 结果分析

运行上述代码后，我们获得了两个函数执行时间的统计数据。以下是详细的测试结果：

#### JWT Token 生成性能

- **平均时间**: 1.0511 μs

- **标准偏差**: 0.0007 μs

- 异常值

  : 发现814个异常值（8.14%）

  - 538个高轻微异常值（5.38%）
  - 276个高严重异常值（2.76%）

#### ciftl-rs Token 生成性能

- **平均时间**: 968.38 ns

- **标准偏差**: 0.33 ns

- 异常值

  : 发现826个异常值（8.26%）

  - 518个高轻微异常值（5.18%）
  - 308个高严重异常值（3.08%）

从结果可以看出，`ciftl-rs`生成令牌的平均时间约为968.38纳秒，而JWT生成令牌的平均时间约为1.0511微秒。这意味着`ciftl-rs`在生成令牌方面比JWT快约10%。