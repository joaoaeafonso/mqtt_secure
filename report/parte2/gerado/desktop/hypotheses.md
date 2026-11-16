# Hipóteses — evidência (desktop-20261115)

Contexto: —. Valores: mediana [IC 95 %].

## H1 — custo do envelope AES-GCM pequeno face à latência da rede
- CPU do gateway, K1→K3: 4.0 [3.6, 4.5] (≠ 0) µs/msg
- latência p50, K1→K3: 22.0 [16.0, 24.0] (≠ 0) µs; latência p50 em K1: 104.0 [102.0, 109.5] µs

## H2 — validade, anti-repetição e chave–tópico quase sem custo
- validade (K3→K4): CPU -0.1 [-0.5, 0.4] (IC inclui 0); p99 2.5 [-10.0, 17.0] (IC inclui 0)
- anti-repetição (K3→K5): CPU 0.0 [-0.6, 0.5] (IC inclui 0); p99 9.0 [-5.0, 15.0] (IC inclui 0)
- chave–tópico (K6→K7): CPU 0.6 [-0.0, 1.2] (IC inclui 0); p99 -8.0 [-13.0, 7.0] (IC inclui 0)

## H3 — Ed25519 claramente mais caro do que AES-GCM
- K8→K9: CPU 132.3 [132.0, 132.9] (≠ 0) µs/msg; p99 295.5 [288.5, 301.5] (≠ 0) µs

## H4 — custo do TLS concentrado no estabelecimento da ligação
- estabelecimento: K0 160.6 [110.6, 210.6] ms, K1 214.4 [214.4, 214.5] ms; CPU por ligação K0 0.6 [0.6, 0.6], K1 3.1 [3.0, 3.1] ms
- por mensagem: K0→K1 CPU 3.7 [3.3, 4.0] (≠ 0) µs/msg; TLS com envelope (K10→K7) 2.4 [2.0, 2.7] (≠ 0) µs/msg

## H5 — sob inundação, a limitação antes da criptografia reduz o CPU do gateway
- CPU do gateway sob inundação (attacks.csv, ataque flood, mediana das repetições): K7 3.8 %, K8 3.8 %
- por mensagem recebida: K7 30.1 µs, K8 30.0 µs; rejeitadas pelo limite: K7 0.0, K8 1 564

## AES por hardware vs ChaCha20 (QP4)
- K8→K11: CPU 0.5 [0.1, 1.3] (≠ 0) µs/msg (ver também microbench.csv com e sem aceleração AES)
