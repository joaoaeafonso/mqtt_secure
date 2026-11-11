# Plano de implementação — Parte 2

Este plano transforma o que o relatório da Parte 1 promete (Secções 6 e 7) em
trabalho concreto no repositório. O relatório é teórico; este documento é interno
e parte do estado real do código.

Avaliação da Parte 2 (20 valores): implementação 8, testes e comparação de
resultados 6, validação do protótipo 4, vídeo 2.

## 1. Estado atual: o que o relatório promete e o que já existe

| Promessa do relatório | Estado no repositório | Onde |
|---|---|---|
| Envelope de 25 octetos, tópico nos dados associados, modos cifra/autenticação/assinatura (§6.4) | Feito | `modules/security/src/envelope.cpp`, `security_layer.cpp` |
| Ordem de verificação (Tab. 11): formato, modo, validade, verificação, chave–tópico, janela (§6.5) | Feito | `security_layer.cpp` (unprotect) |
| Validade temporal Δa = 60 s, Δs = 5 s (§6.6) | Feito; **ajustável por fluxo** (`FreshnessRule`) | `security_layer.hpp`, `--freshness-rule` no *gateway* |
| Janela anti-repetição w = 64 por chave (§6.6) | Feito, em memória | `replay_guard.cpp` |
| Restrição chave–tópico (§6.7) | Feito | `key_policy.cpp` |
| Chaves por época, rotação com período de graça, revogação (§6.8) | Feito | `tools/loadgen/pki.py`, `lab.py` |
| *Token bucket* por tópico com balde partilhado acima do limite (§6.9) | Feito | `modules/limits/src/rate_limit_layer.cpp` |
| Camada 1: TLS 1.3, mTLS, palavras-passe, ACL `%u`, `clientid` ligado, limites de pacote e ligações (§6.3) | Feito | `tools/loadgen/broker.py`, `lab.py` |
| ChaCha20-Poly1305 como alternativa ao AES-GCM (§6.4) | Feito (WP1): algoritmo como atributo da chave | `openssl/chacha20_poly1305_cipher.cpp`, `key_store.hpp`, `msec_envelope.py` |
| Configurações K0–K10 (Tab. 14) | Feito | `lab.py` (`Level("K0")`…`Level("K10")`) |
| Configuração K11 (K8 com ChaCha20) | Feito | `lab.py` (`Level("K11")`), perfil `11_full_key_binding_chacha20` |
| *Microbenchmarks* de 16 B a 64 KiB (§7.3) | Feito | `benchmarks/pipeline_benchmarks.cpp` |
| Laboratório de carga com sensores e atacante noutras máquinas (§7.3) | Feito | `cluster.py`, `agent.py`, `sensors.py`, `attacker.py` |
| Latência p50/p99, CPU do *gateway* por mensagem, CPU do *broker* (Tab. 15) | Feito | `lab.py` |
| Memória máxima (Tab. 15) | Feito (WP4): pico de RSS do *gateway* e do *broker* por execução | `procstats.py`, `lab.measure` |
| Octetos por mensagem, separando *payload*, MQTT e TLS (Tab. 15) | Feito (WP4): *socket* do *gateway* (`ss`) + formatos | `procstats.py` (`bytes_*`) |
| Estabelecimento de ligação (Tab. 15, H4) | Feito (WP4) | `connect-test` no *gateway*, `connect_ms_p50` |
| Ataques da Tab. de ataques (§7.4) | Feito (WP3), com controlos negativos; *broker* ativo por *relay* em texto claro | `attacker.py`, `relay.py`, `scenarios.py`, `attacks.py` |
| Requisitos por caso de uso e critério de Pareto (§7.5) | Feito (WP5) | `tools/analysis/analyze.py` |
| 10 repetições em ordem aleatória, *bootstrap* por execução, diferença das diferenças (§7.6) | Feito (WP5) | `loadgen.py campaign`, `analyze.py` |
| Artefacto reprodutível: manifesto, sementes, dados brutos, *scripts* de análise (§7.7) | Feito (WP5) | `campaign.py`, `manifest.py`, `results/`, `tools/analysis/` |
| Testes automatizados das regras de aceitação (§7.7) | Feito (WP2): um teste por regra, verificados por mutação | `tests/acceptance_tests.cpp` |

## 2. Pacotes de trabalho

Cada pacote tem critério de aceitação verificável. A ordem da Secção 3 respeita as
dependências.

### WP1 — ChaCha20-Poly1305 (K11)

- Implementar `modules/security/src/openssl/chacha20_poly1305_cipher.cpp` sobre a
  interface AEAD existente (`aead_cipher.hpp`).
- Tornar o algoritmo um atributo da chave: acrescentar o campo ao `KeyStore` e ao
  formato dos ficheiros de chaves (`pki.py`, `write_keys`), e escolher a cifra pelo
  identificador de chave no envio e na receção. O formato do envelope não muda.
- Atualizar o lado Python (`tools/loadgen/msec_envelope.py`) e o dissector
  (`tools/wireshark/msec.lua`), se dependerem do algoritmo.
- Acrescentar `Level("K11", …)` em `lab.py` e a configuração aos *benchmarks*.
- **Aceitação:** vetores de teste da RFC 8439 §2.8.2 passam; K11 corre no
  laboratório; uma chave AES não decifra um envelope ChaCha20 e vice-versa.

### WP2 — Regras de aceitação e configuração

- Validade temporal **por fluxo** (o relatório diz "deverão ser ajustáveis por
  fluxo", §6.6): Δa e Δs por filtro de tópico, com o valor global por omissão.
- **Validação de dependências** (§7.7, req. 1): recusar configurações com validade
  temporal, anti-repetição ou chave–tópico ativas e o envelope desligado, no
  `SecurityLayer` e na validação de configuração do laboratório.
- **Reinício do recetor** (limitação de §6.11): **decidido: nova época.** Depois de
  um reinício, o recetor só aceita mensagens de chaves de uma época posterior à
  última que registou antes de parar, reutilizando a rotação por época que já
  existe; não se persiste a janela a cada mensagem. **Registo durável (feito):**
  `IEpochStore`/`FileEpochStore` guarda a época mais recente aceite num ficheiro
  substituído atomicamente (escrita, `fsync`, `rename`), uma vez por rotação e
  antes de aceitar a primeira mensagem da nova época; falhas de leitura ou
  escrita rejeitam (falha fechada). O *gateway* usa `--epoch-state`.
- **Testes** (§7.7, req. 2): um teste por linha da Tab. 11 (ordem de verificação),
  janela (limites `w`, reordenação, números forjados não avançam a janela), política
  de modos, chave–tópico com `%u`, validade nos limites Δa e Δs.
- **Aceitação:** os testes novos falham quando a regra correspondente é removida.

### WP3 — Ataques em falta (Tab. de ataques, §7.4)

Novos cenários em `scenarios.py` (e capacidades em `attacker.py`), cada um com a
previsão do desenho e um **controlo negativo** (a mesma configuração sem a camada):

| Cenário novo | O que o atacante faz | Camada que deve impedir |
|---|---|---|
| `republish-topic` | copia um envelope capturado para outro tópico | tópico nos dados associados |
| `stolen-key-other-topic` | publica com a chave de `sensor-1` no tópico de `sensor-2` | restrição chave–tópico (e ACL) |
| `old-unseen-message` | entrega uma mensagem antiga nunca vista (sequência nova) | validade temporal; a janela sozinha aceita |
| `downgrade-mode` | altera o modo sem a chave; e usa um modo válido não aceite | modo nos dados associados; política do recetor |
| `receiver-forgery` | com o material do *gateway*, forja uma ordem | só o modo de assinatura |
| `slow-connections` | ocupa ligações ao estilo SlowITe | `max_connections` no *broker* |
| `active-broker` | *broker* que altera, redireciona ou atrasa mensagens | envelope (alterações); nada evita a supressão |
| `eavesdrop-network` | captura no fio, separada da escuta no *broker* | TLS (rede); modo de cifra (*broker*) |

- O `active-broker` precisa de um intermediário controlável (por exemplo, um
  *proxy* MQTT entre clientes e Mosquitto). É o item mais incerto: se não couber no
  tempo, fica documentado como não ensaiado.
- **Aceitação:** `loadgen.py scenarios` reporta PASS/FAIL para todos, com o
  controlo negativo a falhar como previsto.

### WP4 — Métricas em falta (Tab. 15)

- Memória máxima (RSS) do *gateway* e do *broker* por execução.
- Octetos por mensagem separados em *payload*, envelope, MQTT e TLS, a partir da
  captura (`capture.py`).
- Tempo de estabelecimento e de restabelecimento de ligação (TLS), para testar H4.
- Tempo de recuperação após ataque.
- **Aceitação:** cada métrica aparece no CSV de cada execução.

### WP5 — Procedimento experimental e reprodutibilidade (§7.6, §7.7)

- Repetições: 10 por configuração, ordem aleatória com semente registada, 3 s de
  estabilização e 30 s de medição.
- Exportar com cada execução: configuração completa, manifesto (commit git, SO,
  OpenSSL, Mosquitto, compilador, modelo do processador), sementes e ordem dos
  ensaios, e os dados brutos por execução (não só agregados).
- *Scripts* de análise (Python, em `tools/analysis/`):
  - mediana e IC 95 % por *bootstrap* sobre execuções;
  - custo marginal por camada e diferença das diferenças para os pares da §7.6;
  - S(c), C(c), filtro por caso de uso, fronteira de Pareto e c* (Eq. da §7.5);
  - geração das tabelas e figuras do relatório da Parte 2.
- Fixar antes da campanha (e registar): pesos w_a e v_m, R_alvo e L_max, para não
  serem escolhidos depois de ver os resultados. **Pendente:** o grupo vai validar a
  proposta (w_a = 1; v_m = 0,4 processador, 0,4 latência p99, 0,2 restantes;
  R_alvo e L_max após um piloto no Pi, antes da campanha).
- **Aceitação:** apagar `build/` e correr um comando reconstrói as tabelas a partir
  dos dados brutos.

### WP6 — Campanha no Raspberry Pi 5 (§7.3)

- Compilar nativamente no Raspberry Pi 5; registar o modelo, a memória e as versões.
- Nível 1: *microbenchmarks* K0–K11 para 16 B, 256 B, 4 KiB e 64 KiB, com e sem
  `OPENSSL_armcap=0`.
- Nível 2: *broker* e *gateway* no Pi; sensores e atacante noutras máquinas
  (`cluster.py`); aumentar carga até à saturação.
- Repetir os dois níveis no computador de secretária, como referência.
- **Aceitação:** um conjunto de dados brutos completo por plataforma.

### WP7 — Relatório da Parte 2 e vídeo

- Confirmar ou refutar H1–H5 e cada linha da Tab. de ataques, com os dados.
- Recomendação por caso de uso (telemetria não sensível, sensível, ordens).
- Vídeo: demonstração do laboratório (ataques a passar e a ser rejeitados ao ligar
  cada camada) e resultados principais.

## 3. Ordem sugerida

1. **WP2 (testes e validação)** e **WP1 (ChaCha20)** em paralelo: são a base do
   protótipo e pesam na implementação (8 valores).
2. **WP3 (ataques)** e **WP4 (métricas)**: dão a matéria dos testes e comparações
   (6 valores).
3. **WP5 (procedimento e análise)**: tem de estar pronto **antes** da campanha.
4. **WP6 (campanha)**, só depois de 1–3 estarem fechados, para não repetir medições.
5. **WP7 (relatório e vídeo)**.

## 4. Riscos

| Risco | Mitigação |
|---|---|
| *Broker* ativo (`active-broker`) mais difícil do que previsto | Fazê-lo por último no WP3; se falhar, declarar como não ensaiado |
| Aceleração AES não desligável no Pi como esperado | Verificar `OPENSSL_armcap=0` no primeiro dia de campanha; o K11 dá a comparação de qualquer forma |
| Ruído nas medições (temperatura, *throttling* do Pi) | Registar frequência e temperatura; dissipador; ordem aleatória |
| Resultados contrariam as hipóteses | Não é falha: o relatório diz que as hipóteses podem ser refutadas |

## 5. Regras de trabalho

- Os *commits* são feitos pelo utilizador, depois de rever cada pacote; não se criam ramos nem *commits* automaticamente.

## 6. Fora do âmbito (decidido)

- HMAC como modo próprio (o GMAC já cobre autenticação sem cifra).
- *Nonces* por contador (fica como limitação; os aleatórios com rotação bastam).
- Modo cifra seguida de assinatura: só se sobrar tempo; o relatório apresenta-o
  como possível extensão.

## 7. Estado da implementação (2026-11-05)

WP1–WP5 estão implementados (ver a tabela da Secção 1 e `docs/evaluation.md`).
Falta o que depende do Pi e do grupo:

- **Validar os parâmetros** em `tools/analysis/params.toml` (proposta: w_a = 1;
  v_m = 0,4 CPU, 0,4 p99, 0,05 para cada uma das restantes) e fixar R_alvo e
  L_max após o piloto; mudar `status` para `"fixed"` antes da campanha. Até lá a
  análise marca tudo como PROVISÓRIO.
- **WP6**: compilar no Pi, `tools/analysis/microbench.py` (nível 1, com e sem
  `OPENSSL_armcap=0`), `loadgen.py campaign` e `loadgen.py attacks` (nível 2),
  e o mesmo no computador de secretária.
- **WP7**: relatório e vídeo, a partir de `tools/analysis/analyze.py`.

Calibração de Δa e Δs (§6.6, "a calibrar na segunda parte"): feita. Cada
execução regista o desvio de relógio dos agentes e a cauda da latência, e
`analyze.py` propõe Δa e Δs em `calibration.md` (precisa de sensores em agentes).

Observações dos primeiros ensaios no portátil que interessam ao relatório:

- **Ocupação de ligações**: o limite `max_connections` protege os recursos do
  *broker* e mantém os clientes já ligados, mas o atacante ocupa as vagas
  livres; se o *broker* reiniciar durante o ataque (por exemplo, ao aplicar o
  próprio limite), o atacante pode ficar com todas as vagas e nenhum sensor
  volta a ligar-se.
- **Chave roubada**: mensagens aceites com uma chave roubada (nos controlos
  negativos) avançam a janela anti-repetição da vítima, que passa a rejeitar o
  tráfego legítimo até à rotação de chaves.
- **Falsificação pelo recetor** através de um *broker* legítimo com ACL: a ACL
  já impede um atuador de publicar nos tópicos de ordens dos outros (observado
  em K1, sem envelope); só com um *broker* ativo ou sem ACL se observa a
  diferença entre AES e assinatura (cenários `receiver-forgery*`).
- **Dispositivo comprometido e sessão MQTT**: ao ligar-se com a identidade do
  dispositivo, o atacante toma-lhe a sessão (o *broker* desliga o legítimo) e
  os dois alternam enquanto o ataque dura — negação de serviço da vítima.
  O laboratório não detetava esta desconexão (paho com ciclo manual mantém
  `is_connected()` verdadeiro); corrigido em `sensors.py`. Desde 2026-11-11
  isto só acontece com `attacker.stolen_exclusive = false` (ver Secção 8).
- **Resolvido (2026-11-11)**: o contador `republished_ok` do *gateway*
  registava 1–2 falsos positivos por janela sem atacante ligado. Causa: a
  deteção usava só o instante de envio (ns); a taxas de saturação, dois
  sensores em processos diferentes tiram o mesmo nanossegundo de vez em quando
  (efeito de aniversário, ≈ N²/(T·10⁹) pares por janela). Reproduzido a
  16 000 msg/s (1, 0, 1 por janela de 15 s) e corrigido: a deteção passa a ser
  por dispositivo e instante (0, 0, 0). O critério do ataque `republish-topic`
  continua relativo (≥ 50 % das cópias aceites).
- **Estabelecimento de ligação**: `connect_ms_p50` inclui a espera interna do
  cliente Paho C++ (≈ 200–300 ms também sem TLS); para H4, o indicador útil é
  `connect_cpu_ms` (0,8 ms sem TLS vs 3,3 ms com mTLS no portátil).

## 8. Revisão de 2026-11-11 (antes da campanha)

Revisão completa do código, da documentação e do procedimento. Corrigido:

- `campaign --vary` não funcionava (a lista de valores era lida carácter a
  carácter) e, com `load.payload` ou `load.rate` como fator, os limites do nível
  eram calculados para a carga anterior (recusado em K8/K9/K11). Nível e fatores
  são agora aplicados num só passo (`lab.level_patch`); a matriz de ataques e a
  saturação correm sempre com a carga base.
- Com sensores em agentes, `loss_pct` tinha um erro de ±0,5 s por janela (±3 %
  numa janela de saturação de 15 s, contra um critério de 1 %). Os agentes
  passam a reportar a pedido nos limites da janela (protocolo de controlo v3:
  controlador e agentes têm de usar o mesmo *checkout*).
- Falsos positivos de `republished_ok` (Secção 7).
- **Matriz de ataques com dispositivo comprometido**: o atacante e o sensor
  verdadeiro disputavam a sessão MQTT (o mesmo identificador de cliente) e o
  atacante só estava ligado ≈ 5–10 % do tempo. A "inundação" ficava em
  ≈ 14 msg/s e era dada como impedida em K3, K6 e K7 (sem limitação), porque o
  critério exigia o atacante ligado no último instante da janela. Agora o
  dispositivo comprometido fica calado enquanto o atacante o controla
  (`attacker.stolen_exclusive`, por omissão), a inundação atinge a taxa pedida
  e o critério usa as mensagens enviadas. A disputa de sessão (observação da
  Secção 7) reproduz-se com `attacker.stolen_exclusive = false`.
- Análise: o contexto das tabelas principais dependia da ordem aleatória das
  execuções; separador de milhares LaTeX nos ficheiros Markdown; H5 usava só a
  última repetição do ataque; `analyze.py` e `microbench.py` não eram
  executáveis.
- Nível 1: `OPENSSL_armcap=0` desliga também o NEON, de que o ChaCha20
  depende; em ARM o *script* acrescenta uma execução com `OPENSSL_armcap=1`
  (só NEON), que é a comparação justa para a QP4.
- Documentação desatualizada (README dizia que o K11 não estava implementado;
  contagens de testes e de cenários; módulos novos por descrever).

Decisões tomadas em 2026-11-11 (`status = "fixed"`):

- **R_alvo e L_max** (decidido 2026-11-11, após três pilotos no Pi): cenário de
  monitorização industrial, 1 000 sensores a 10 Hz → R_alvo = 10 000 mensagens/s
  para a telemetria; ordens a 100 atuadores, até 10/s cada → R_alvo = 1 000
  mensagens/s para as ordens; L_max = 50 ms. R_alvo por caso de uso é um desvio
  ao plano da Parte 1 (um só R_alvo): com um só valor de 10 000, o caso
  "ordens" ficava sem configuração exequível (só K9 dá prova de origem e
  sustenta ≈ 5 000 mensagens/s). Declarar em `03-metodo.tex` (Desvios ao plano).

- **Pesos dos ataques** (decidido 2026-11-11): o conjunto 𝒜 do código tem 13
  ataques para as 11 linhas da tabela do relatório (escuta = rede + *broker*;
  injeção e adulteração = dois ataques). Cada um desses quatro pesa 0,5 em
  `[attack_weights]`, para cada linha da tabela pesar 1.
- **Escuta no *broker*** (decidido 2026-11-11: fica só no relatório, sem
  alterar o código): o ataque `eavesdrop-broker` mede um subscritor de `#` sem
  credenciais, que K1 já impede; um *broker* curioso lê o conteúdo em K1, K2 e
  K9. S(c) não distingue estes casos; o filtro por caso de uso sim (telemetria
  sensível exige o modo de cifra). A escrever nas ameaças à validade (WP7).
- **Estabelecimento de ligação no custo** (decidido 2026-11-11):
  `connect_ms_p50` varia em degraus de ≈ 100 ms (esperas internas da biblioteca
  Paho C); entra em `[cost_weights]` o `connect_cpu_ms`, que distingue o TLS.
