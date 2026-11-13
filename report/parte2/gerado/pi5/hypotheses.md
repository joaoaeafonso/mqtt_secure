# Hipóteses — evidência (pi5-20261113)

Contexto: —. Valores: mediana [IC 95 %].

## H1 — custo do envelope AES-GCM pequeno face à latência da rede
- CPU do gateway, K1→K3: 7.2 [6.8, 7.8] (≠ 0) µs/msg
- latência p50, K1→K3: 25.0 [22.5, 31.5] (≠ 0) µs; latência p50 em K1: 149.0 [147.0, 150.5] µs

## H2 — validade, anti-repetição e chave–tópico quase sem custo
- validade (K3→K4): CPU 0.6 [-0.1, 1.1] (IC inclui 0); p99 -5.0 [-10.0, 3.5] (IC inclui 0)
- anti-repetição (K3→K5): CPU 0.2 [-0.4, 0.9] (IC inclui 0); p99 -4.0 [-9.5, 15.5] (IC inclui 0)
- chave–tópico (K6→K7): CPU 1.3 [0.7, 1.8] (≠ 0); p99 -7.5 [-36.5, 9.5] (IC inclui 0)

## H3 — Ed25519 claramente mais caro do que AES-GCM
- K8→K9: CPU 151.5 [150.5, 152.3] (≠ 0) µs/msg; p99 463.5 [449.0, 499.0] (≠ 0) µs

## H4 — custo do TLS concentrado no estabelecimento da ligação
- estabelecimento: K0 210.7 [210.7, 210.7] ms, K1 216.2 [216.1, 216.2] ms; CPU por ligação K0 0.8 [0.8, 0.8], K1 4.2 [4.1, 4.3] ms
- por mensagem: K0→K1 CPU 7.9 [7.5, 8.3] (≠ 0) µs/msg; TLS com envelope (K10→K7) 5.5 [5.2, 5.7] (≠ 0) µs/msg

## H5 — sob inundação, a limitação antes da criptografia reduz o CPU do gateway
- CPU do gateway sob inundação (attacks.csv, ataque flood, mediana das repetições): K7 5.2 %, K8 5.1 %
- por mensagem recebida: K7 40.5 µs, K8 39.7 µs; rejeitadas pelo limite: K7 0.0, K8 1 559

## AES por hardware vs ChaCha20 (QP4)
- K8→K11: CPU 1.5 [1.1, 2.1] (≠ 0) µs/msg (ver também microbench.csv com e sem aceleração AES)
