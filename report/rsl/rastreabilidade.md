# Rastreabilidade das afirmações

Cada linha liga uma afirmação do relatório ao sítio exato da fonte de onde foi tirada. A localização na fonte é a referência estável; os números de linha da coluna «Onde» são indicativos, porque o relatório foi revisto depois de registados (as secções do relatório continuam válidas).

Os IDs (E01–E17) são os da tabela de estudos (`tab:estudos`) do relatório. Foram excluídos por CI4, por não se ter obtido o texto integral, os estudos de Lohachab e Karambir, de Andy et al. e de Hernández Ramos et al. As tabelas do relatório são referidas pelo rótulo: «Tab. comparação» (`tab:comparacao`), «Tab. proposta» (`tab:proposta-vs`), «Tab. revisões» (`tab:revisoes`), «Tab. qualidade» (`tab:qualidade`).

- **Onde**: `ficheiro.tex:linha` no relatório.
- **Localização**: secção / figura / tabela / equação da fonte e página. Salvo indicação, a página é a do PDF consultado; quando difere da paginação publicada, a correspondência está no cabeçalho de cada fonte.
- **Estado**: `OK` confirmado no texto integral · `CORRIGIDO` a versão anterior do relatório dizia outra coisa; o valor indicado é o que está no relatório · `CITADO` faltava a citação, que foi acrescentada · `SEM ACESSO` sem texto integral (só se usa o resumo).

---

## E11 — Dahlmanns et al. 2021 (ENTRUST) `dahlmanns2021entrust`

Fonte: cópia de autor, <https://www.comsys.rwth-aachen.de/fileadmin/papers/2021/2021-dahlmanns-entrust.pdf> (10 pp.; p. *n* do PDF = p. 77+*n* das atas SaT-CPS'21, pp. 78–87).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:162 | ENTRUST: segurança fim-a-fim baseada num servidor de chaves, sem alterar o protocolo | §5 (p. 5) e §5.3 *Takeaway* (p. 7) | "key server-based end-to-end security in publish/subscribe systems"; "transparently deployable without any changes to the underlying PubSub protocol" | OK |
| 05-resultados.tex:316 | O *broker* expõe todo o conteúdo | §1 (p. 1) | "brokers need to be fully trusted" | OK |
| Tab. comparação / Tab. proposta, col. C, I, Au | Confidencialidade, integridade, autenticação | §5.3 (p. 7); §6 (p. 7) | "ENTRUST relies on ChaCha20 [...] and the Poly1305 authenticator" | OK |
| Tab. comparação, col. Az = – | Sem autorização | §5.2 (p. 6), Fig. 3 "Evaluate ACL" | "the key server checks whether the specific client is allowed to access the topics [...] using an access control list (ACL)" | CORRIGIDO → ✓ (autorização no servidor de chaves) |
| Tab. comparação, col. R = – | Sem anti-repetição | §5.3 (p. 7); §6 (p. 7) | "publishers in ENTRUST include a publisher-specific message counter into each message [...] subscribers can reliably detect duplicated messages" | CORRIGIDO → ✓ (deteção de duplicados por contador por publicador) |
| Tab. comparação, col. V = – | Sem validade temporal | Fig. 4 (p. 7); §6 (p. 7) | campo *Time Offset*: "at which point in time the next message from this publisher is to be expected" | OK (–): é o intervalo até à próxima mensagem, não um limite de idade; dizê-lo no texto |
| Tab. comparação, col. D = – | — | §5.3 (p. 7) | "they can reliably detect dropped messages" | CORRIGIDO → ● (deteção de mensagens suprimidas) |
| Tab. comparação, col. Restr. = – | Não avaliado em dispositivos restritos | §7 (p. 8) | "three resource-constrained RedBear Duo (ARM Cortex-M3 @ 120 MHz) CPS devices" | CORRIGIDO → ✓ |
| Tab. proposta, col. LT = – | Sem ligação ao tópico | §5 (p. 5) | "a symmetric key per topic" | CORRIGIDO → ● (ligação implícita: chave por tópico, o tópico não entra no MAC) |
| acrescentado | Confiança transferida para o servidor de chaves | §6 (p. 7) | "moving trust from the broker [...] to a key server" | OK |
| novo | *Overhead* de 42 B por mensagem | §7.3 (p. 9) | "ENTRUST adds a small overhead of 42 B to each message" | OK |

## E14 — Van Glabbeek et al. 2022 `vanglabbeek2022flexible`

Fonte: texto integral em PMC9572294 (Europe PMC, *full text XML*); artigo sem paginação interna (Sensors 22(19), 7391).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:164 | −80 % *overhead* de comunicação e −40 % computacional face ao MQTTS, no estabelecimento da ligação | Resumo; §7 | "communication overhead is reduced by 80% and the computational overhead by 40% for the setup of a secure connection on the client side" | OK (nota: o §7 diz "approximately 3 times" para o custo computacional, inconsistente com o resumo; citar o resumo) |
| Tab. comparação, col. Au, NR = – | Sem autenticação nem não repúdio | §3.2; §4.3 "Option 1: Authentication and non-repudiation"; §5.2 | "Thanks to the usage of the Schnorr signature [...] authentication, and non-repudiation are established" | CORRIGIDO → ✓ ✓ |
| Tab. comparação, col. C = ● | Confidencialidade parcial | §4.3 Option 2; §5.2 | "due to the usage of the ECIES algorithm, also confidentiality is obtained" | OK (● = só nas opções 2 e 3) |
| Tab. comparação, col. I = ● | Integridade parcial | §4.3 (assinatura Schnorr sobre M‖T‖ID_G) | M1={ID_G, ID_i, T, M, V, s} | CORRIGIDO → ✓ (assinatura em todas as opções) |
| Tab. comparação, col. P = – | Sem privacidade | §3.2 Option 3; §4.3 Option 3 | "anonymity and unlinkability are also included" | CORRIGIDO → ✓ (opção 3) |
| Tab. comparação, col. V, R = – | Sem frescura nem repetição | §3.4 (último parágrafo); §4.3 (T assinado) | "Since the security mechanisms in the protocol (e.g., use of timestamps) already offer protection against replay attacks" | CORRIGIDO → ● ● (carimbo assinado; não define regra de aceitação nem deduplicação) |
| Tab. comparação, col. BnC = ● | Funciona com *broker* não confiável | §3.1; §6 | "The broker is considered honest but curious"; no protótipo "the broker is responsible of all the security operations [...] not a safe situation" | OK (●); acrescentar a simplificação do protótipo (§6) |
| Tab. comparação, col. Restr. = ✓ | Dispositivos restritos | §6.1; §7 | Raspberry Pi 3B+; "developed for constrained devices" | OK |
| acrescentado | CA totalmente confiável | §3.1; §7 | "An external party, called the CA [...] is considered to be fully trusted" | OK |

## E13 — Prantl et al. 2021 `prantl2021performance`

Fonte: <https://research.spec.org/icpe_proceedings/2021/proceedings/p241.pdf> (p. *n* do PDF = p. 240+*n* das atas ICPE'21).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:175 | O impacto do TLS depende sobretudo da rede e da frequência de restabelecimento | Resumo (p. 1) | "depends on (i) the network situation and (ii) the connection reestablishment frequency" | OK |
| 07-plano-avaliacao.tex:175 | O custo do TLS concentra-se no estabelecimento da ligação | §7 (p. 8) | "the use of TLS negatively impacts the connect time to the broker, especially in settings with higher packet loss" | OK |
| 02-enquadramento.tex:84 | TLS: "custo em dispositivos restritos" | Resumo (p. 1); §7 (p. 8) | "a negative influence of TLS on the performance is noticeable only in deteriorated network situations or at a high reestablishment frequency" | CORRIGIDO → "custo no estabelecimento da ligação, sobretudo com perdas de pacotes" |
| Anexo B:59 / Tab. comparação Restr. | ESP8266, todos os QoS | §4 (p. 3) | "We chose the ESP8266 microcontroller as an MQTT client"; "supports TLS and all three MQTT QoS levels" | OK |
| acrescentado | Usa TLS 1.2 | §4 (p. 3) | "TLS 1.2 using the Windows OpenSSL version" | OK |

## E10 — Segarra et al. 2020 (MQT-TZ) `segarra2020mqttz`

Fonte: preprint de autor arXiv:2007.12442v2 ("authors preprint version of the camera-ready article").

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:170 | *Broker* em ARM TrustZone, avaliado com cargas reais de uma aplicação médica | Resumo (p. 1) | "real-world industrial workloads from a MedTech use-case" | OK |
| Anexo B:50 | TLS mútuo e cifra em duas camadas | Resumo (p. 1); §IV (p. 4) | "We define a mutual TLS-based handshake and a two-layer encryption for end-to-end security using the TEE as a trusted proxy" | OK |
| 05-resultados.tex:328 | Exposição do conteúdo no *broker* | Resumo (p. 1) | "MQTT brokers must process data in clear, hence exposing a large attack surface" | OK |
| Tab. comparação, col. Az = – | — | §IV (p. 4) | "We also leverage Access Control Lists (ACLs) for fine-grained" | CORRIGIDO → ● (ACL no *broker*) |

## E12 — Spielvogel et al. 2021 `spielvogel2021tls`

Fonte: preprint arXiv:2109.01169.

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 02-enquadramento.tex:85; 05-resultados.tex:329 | Um cliente só controla o seu próprio salto | Resumo (p. 1) | "Clients can only control the security level of their own connection to the broker, but they cannot enforce any protection towards other clients" | OK |
| 05-resultados.tex:172 | O *broker* reencaminha independentemente da proteção; proposta de nível mínimo | Resumo (p. 1) | "relays messages regardless of their inbound and outbound protection"; "only forwarding messages via connections which satisfy the desired security levels" | OK |
| Anexo B:56 | Protótipo; medições de *overhead* | Resumo (p. 1); §II-C, Tab. I (p. 3) | "We prototypically implemented our solution [...] and provide detailed overhead measurements" | OK |

## E08 — Vaccari et al. 2020 (SlowITe) `vaccari2020slowite`

Fonte: texto integral em PMC7285273 (Sensors 20(10), 2932).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:126; Anexo B:45 | DoS de baixa taxa que explora a configuração do servidor pelo cliente, eficaz com e sem cifra | Resumo; §4; §5.2.3 | "allowing the client to configure the behavior of the server"; "considering both plain text and encrypted communications" | OK |
| 02-enquadramento.tex:205 | Ligações lentas | §4 | — | OK |
| acrescentado | Defesas no *broker* | §6 "Considerations about Protection from SlowITe" | — | OK, ler §6 antes de citar a defesa concreta |

## E09 — Vaccari et al. 2020 (MQTTset) `vaccari2020mqttset`

Fonte: PMC7698741 (Sensors 20(22), 6578).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:181; Anexo B:48 | Conjunto de dados de tráfego legítimo e de ataques para treinar detetores | Resumo; §3; §3.1 (5 ataques) | "MQTTset, a dataset focused on the MQTT protocol [...] combining the legitimate dataset with cyber-attacks" | OK |

## E16 — Alotaibi et al. 2024 `alotaibi2024secure`

Fonte: PMC10935133 (Sensors 24(5), 1638).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:183; Anexo B:68 | Deteção distribuída em tempo real com H2O; melhor resultado com XGBoost; métricas MSE, RMSE, *log loss* | Resumo; §3; §4.3; §4.5 | "H2O-based distributed machine learning (ML) framework"; "XGBoost algorithm outperforms other H2O models in terms of accuracy" | OK |

## E06 — Malina et al. 2019 `malina2019secure`

Fonte: `rsl/textos/malina2019secure.pdf` (PDF em formato ACM ARES'19, 10 pp., com o DOI na p. 1; não foi possível confirmar se é a versão do editor ou a cópia IACR ePrint 2019/740).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:159; Anexo B:40 | Três níveis de segurança, do controlo de adulteração à autenticação mútua de todas as partes | Resumo (p. 1); §4.2 (p. 4) | "The first security level suits for lightweight data exchanges of non-tampered messages [...] The third security level offers robust long-term security with mutual authentication for all parties" | OK |
| Tab. comparação, col. I, Au = ✓ | — | §4.2 (p. 4); §5.2 (p. 9) | "all versions ensure this property by the Schnorr signature scheme" | OK |
| Tab. comparação, col. NR = – | Sem não repúdio | §4.2 (p. 4); §5.2 (p. 9) | "Data non-repudiation, integrity and authenticity - all versions ensure this property by the Schnorr signature scheme. Only publisher who holds the private key is able to sign the message" | CORRIGIDO → ✓ |
| Tab. comparação, col. V = – | Sem validade temporal | §4.5, Eq. 6 (p. 6) | "t is an actual timestamp (e.g., 8 bytes date and time) that prevents replay attacks"; "the actual timestamp t for checking the newness" | CORRIGIDO → ● (carimbo assinado e verificado; não define a janela de aceitação) |
| Tab. comparação, col. R = – | Sem anti-repetição | §5.2 (p. 9) | "Replay attack protection - all publish messages and subscribe messages in SL2 and SL3 contain the actual time stamp that prevents replaying these messages" | CORRIGIDO → ● (só por carimbo, em SL2/SL3; sem deduplicação dentro da janela) |
| Tab. comparação, col. Az = – | — | §4.5 (p. 6); §4.7 | "B checks if ID_i is presented in the whitelist"; "the subscriber's ID_j for checking if the subscriber has access to this topic" | CORRIGIDO → ● (lista branca e acesso por tópico no *broker*) |
| Tab. comparação, col. C = ● | Confidencialidade parcial | §5.2 (p. 9) | "SL2 and SL3 provide data confidentiality [...] AES-GCM" | OK (●: só SL2/SL3) |
| Tab. comparação, col. BnC = – | — | §4.7 | "B decrypts the ciphertext encrypted by AES-GCM" | CORRIGIDO → ✗ (o *broker* decifra; a confidencialidade é até ao *broker*) |
| Tab. comparação, col. P = ✓ | Privacidade | §5.2 (p. 9) | "SL2 enhances the privacy protection of publishers and subscribers. ID [...] of the publisher is stripped by the broker" | OK |
| Tab. comparação, col. Aval. = –; Anexo B:43 "Não reportada no resumo" | Sem avaliação | §5.1 (p. 8) | "measured by the number of math operations and cryptographic primitives" | CORRIGIDO → A (analítica, contagem de operações) |
| Tab. comparação, col. Restr. = ✓ | — | Resumo (p. 1) | "suitable for constrained and small devices" | OK (desenhado; não avaliado em hardware) |
| Tab. proposta, col. LT = – | Sem ligação ao tópico | §4.5, Eq. 6 (p. 6) | e = H(SL1_2, T, ID_i, M, t, R, G), "T defines the topic" | CORRIGIDO → ✓ (o tópico T está na entrada da assinatura) |
| Tab. proposta, col. RN = – | — | §4.5 Eq. 6: o nível SL está na entrada da assinatura | e = H(SL1_2, ...) | CORRIGIDO → ● (nível autenticado; não há política explícita do recetor) |

## E04 — Calabretta et al. 2018 (MQTT-Auth) `calabretta2018mqttauth`

Fonte: `rsl/textos/calabretta2018mqttauth.pdf` (JCOMSS 14(4), pp. 320–331; p. *n* do PDF = p. 319+*n*).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:143; Anexo B:29 | AugPAKE para confidencialidade; dois *tokens*: autenticação e autorização por tópico | Resumo (p. 1); §IV, Eq. 10–12 (p. 6) | "based on the AugPAKE security algorithm for guaranteeing confidentiality, and onto two tokens which permit to authenticate the usage of a topic and to guarantee authorization"; Auth1 = MAC(SK_P, topic); Auth2 = MAC(SK_P, topic‖SN[‖ClientID]) | OK |
| 03-metodologia.tex:144 | Versão em revista alargada da de conferência | §I (p. 2) | "the contribution of this work, whose preliminary version was presented in [8]" | OK (a ref. [8] do artigo é o SoftCOM 2018, p. 11) |
| Tab. comparação, col. R = – | — | §IV (p. 6) | "a sequence number (SN) [...] as a protection against replay attacks (attempts to reuse Auth2 by other clients)" | OK (–): protege a reutilização do *token*, não a repetição de mensagens; dizê-lo no texto |
| Tab. comparação, col. BnC = – | — | §IV-A (p. 7) | "the broker should be considered as a trusted entity, since it has complete visibility of the exchanged data, as it is in charge of decrypting and encrypting MQTT payloads" | CORRIGIDO → ✗ |
| Tab. comparação, col. Aval. = A, E | — | §V, Tab. II–III (p. 10) | dois *testbeds*: Intel i7 e "two UDOO microcontrollers" (ARM Cortex-A9) | OK |
| Tab. comparação, col. Restr. = – | — | §V (p. 10) | "two UDOO microcontrollers [...] as subscriber and publisher" | CORRIGIDO → ✓ |
| Tab. proposta, col. LT = – | — | §IV, Eq. 10 (p. 6) | Auth1 = MAC(SK_P, topic) | CORRIGIDO → ● (o *token* liga-se ao tópico, mas não ao conteúdo de cada mensagem) |

## E07 — Sadio et al. 2019 `sadio2019lightweight`

Fonte: `rsl/textos/sadio2019lightweight.pdf` (IOTSMS 2019, pp. 119–123; p. *n* = p. 118+*n*).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:161; Anexo B:43 | ChaCha20-Poly1305 fim-a-fim; protótipo Arduino UNO; memória e tempo de execução | Resumo (p. 1); §IV-A (p. 4) | "A prototype of the proposed solution is implemented on constrained nodes like Arduino UNO. The paper mainly provides results related to memory footprint and execution time" | OK |
| 05-resultados.tex:327 | O TLS é inadequado a nós restritos | Resumo (p. 1); §I (p. 1) | "do not support conventional security protocols such as Transport Layer Security (TLS)"; "TLS did not ensure end to end encryption and on the other is 'too heavy'" | OK |
| Tab. comparação, col. BnC = ✓ | *Broker* não lê o conteúdo | §IV-A (p. 4) | "the MQTT-SN Gateway, MQTT Broker and other unauthorized entities cannot read the message content" | OK |
| Tab. proposta, col. LT = – | — | §IV-A (p. 4) | "MQTT-SN ID can be used as ADD" | OK (–): os dados associados são o ID, não o tópico |
| novo | Gestão de chaves fica para trabalho futuro | §V (p. 5) | "needs a best secret key management when the number of nodes increases" | OK |

## E01 — Singh et al. 2015 `singh2015secure`

Fonte: `rsl/textos/singh2015secure.pdf` (CSNT 2015, 6 pp.).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:149; Anexo B:18 | SMQTT e SMQTT-SN: KP/CP-ABE sobre ECC leve | Resumo (p. 1); §III-B (p. 2) | "SMQTT and SMQTT-SN [...] based on Key/Ciphertext Policy-Attribute Based Encryption (KP/CP-ABE) using lightweight Elliptic Curve Cryptography" | OK |
| 05 C4; Tab. comparação Aval. = E | Implementação em três portáteis, a que os autores chamam simulação | Resumo (p. 1); §VII-A (p. 5) | "through simulations"; "three laptops connected in 802.3 network and simulated as IoT devices"; implementação com Eclipse Paho e Mosquitto | CORRIGIDO → E (antes S), com nota no texto; os portáteis de Calabretta já contavam como E |
| 03-metodologia.tex:78 | Visa o MQTT-SN | Resumo (p. 1) | "SMQTT and SMQTT-SN" | OK |
| Tab. comparação, col. BnC = ● | Funciona parcialmente com *broker* não confiável | §III-B (p. 2), Fig. 1 | "Broker (trusted third party) renders the function of a Public Key Generator (PKG) generates the master secret key" | CORRIGIDO → ✗ (o *broker* é o PKG e gera a chave mestra) |
| Tab. comparação, col. Az = ✓ | Autorização por política ABE | §III-B (p. 2) | política de acesso KP/CP-ABE | OK |

## E05 — Dinculeană e Cheng 2019 `dinculeana2019vulnerabilities`

Fonte: `rsl/textos/dinculeana2019vulnerabilities.pdf` (Appl. Sci. 9(5), 848; 10 pp.).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:157; Anexo B:34 | *Value-to-HMAC*: confidencialidade e integridade com um só mecanismo, mais rápido do que cifra simétrica | Resumo (p. 1); §3.2 (pp. 3–4); §5 | "will achieve better performance than a symmetric-key encryption algorithm, while ensuring the confidentiality and integrity of information through the use of one mechanism" | OK |
| Tab. comparação e Tab. proposta, col. BnC = ✓ | Funciona com *broker* não confiável | §5 (p. 7) | "because the keys are not stored on the broker"; "only the nodes that possess the secret key can recover the original value" | CORRIGIDO → ✓ (a nota anterior, «o artigo não diz que o *broker* fica sem a chave», estava errada; detetado pela revisão cética) |
| Tab. comparação, col. Restr. = ✓ | — | §3.1 (p. 3) | "The Onion Omega2+ was chosen as the single board computer" | OK |
| Tab. comparação, col. V, R = – | — | §6 (p. 8) | "Additional mechanisms need to be implemented to deal with client authentication, key distribution [...] and replay attacks" | OK (✗ por desenho: os autores excluem-no explicitamente) |

## E17 — Javadi et al. 2026 (CMAP) `javadi2026cmap`

Fonte: `rsl/textos/javadi2026cmap.pdf` (IEEE Access 14, 2026; páginas 60836–60852; p. *n* do PDF = 60835+*n*).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:133; Anexo B:70 | Autenticação mútua sem certificados sobre ECC, verificada formalmente, avaliada em Raspberry Pi | Resumo (p. 1); §V-B (pp. 10–11); §VI-B | "built on elliptic-curve cryptography. CMAP removes the reliance on digital certificates"; "Experimental evaluations conducted on Raspberry Pi platforms" | OK |
| 05-resultados.tex:296; 06-proposta.tex:305; 09-conclusoes.tex:30 | Verificação formal | §V-B (p. 10) | "This section formally proves the security of CMAP within the Random Oracle Model (ROM). The conducted ROM proof is a game-based approach" | OK, mas precisar: "prova de segurança no modelo do oráculo aleatório", não verificação automática |
| 05-resultados.tex:327 | O TLS é inadequado a nós restritos | Resumo (p. 1) | "TLS and password-based authentication, are often ill-suited for resource-constrained IoT devices" | OK |
| Tab. comparação, col. Aval. = F, E, S | — | Resumo; §V-B; §VI-B; §VI-C | "NS-3 simulations" | OK |
| Tab. comparação, col. R = – | — | §V-A3 (p. 9) | "3) REPLAY ATTACK" (resistência baseada em *nonces* frescos, só na autenticação) | OK (–): é anti-repetição do *handshake*, não das mensagens; dizê-lo no texto |
| Tab. comparação, col. BnC = – | — | §IV (p. 7) | "a central HIS server as the MQTT broker gateway G_g"; o *broker* é a parte autenticada e coordena o registo | CORRIGIDO → ✗ |
| Tab. comparação e 13, col. C, I | — | Resumo (p. 1); §IV-B–C (p. 7) | deriva a chave de sessão SK_i,g, mas não especifica a proteção das mensagens publicadas; o resumo diz apenas "while preserving confidentiality and integrity properties" | CORRIGIDO → ● ● (antes ✓ ✓) |

## E02 — Niruntasukrat et al. 2016 `niruntasukrat2016authorization`

Fonte: `rsl/textos/niruntasukrat2016authorization.pdf` (ICC Workshops 2016, 6 pp.).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:139; Anexo B:20 | OAuth 1.0a adaptado a nós restritos sem interface; atrasos de autorização mínimos numa plataforma real | Resumo (p. 1); §III (pp. 2–3); §IV (pp. 4–5) | "The design is based on OAuth 1.0a"; "lack of node's user interface"; "implemented on a real MQTT-based IoT service platform [...] Authorization delay and message overhead are minimal" | OK |
| Tab. comparação, col. Restr. = ✓ | — | §IV (p. 4) | "we measure the authorization delay of three types of devices: Arduino Mega [...]" | OK |
| Tab. comparação, col. R = – | — | §V-C | "C. Protection against replay attack" (*timestamp* e *nonce* no pedido de autorização) | OK (–): protege o pedido de *token*, não as mensagens publicadas; dizê-lo no texto |

## E03 — Rizzardi et al. 2016 (AUPS) `rizzardi2016aups`

Fonte: `rsl/textos/rizzardi2016aups.pdf` (versão de autor, 15 pp.; Information Systems 62, 2016).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:141; Anexo B:23 | Estende o MQTT com gestão de chaves e aplicação de políticas; código aberto | Resumo (p. 1); §III-C; §IV | "extending MQTT by means of a key management framework and a policy enforcement one [...] released as open source under Apache v.2 license" | OK |
| Tab. comparação, col. Aval. = – | Sem avaliação | §IV-A "Robustness Evaluation"; §V "Evaluation Scenario" (§V-A *overhead*, §V-B latência, §V-C computação) | "Section V analyses a prototypical implementation of the proposed solution and presents performance evaluation results" (§I, p. 2) | CORRIGIDO → A, E |
| Tab. comparação, col. Restr. = – | — | §V-A (p. 12) | "NOS runs on a Raspberry Pi with 512MB of RAM" | CORRIGIDO → ✓ |
| Tab. comparação, col. Az = ✓ | Chaves temporárias por tópico para controlo de acesso | §IV (p. 9) | "KTM is in charge of managing temporary keys for topics access control" | OK |

## E15 — Buccafurri et al. 2023 (MQTT-A) `buccafurri2023mqtta`

Fonte: `rsl/textos/buccafurri2023mqtta.pdf` (IEEE IoT J. 10(17), pp. 15443–15463; p. *n* do PDF = p. 15442+*n*).

| Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|
| 05-resultados.tex:188; Anexo B:65 | Rede de *brokers* intermédios (*bridges*) impede o *broker* final de identificar a origem/destino | Resumo (p. 1); §V | "P2P collaboration of intermediate bridge brokers, which forward the requests of clients so that the final broker cannot understand the actual source/destination" | OK |
| Anexo B:65–67 | *Brokers* em nuvem em vários países; latência e *goodput* | Resumo (p. 1); §VIII-A, §VIII-B, §VIII-C | "deploying the bridge brokers on cloud platforms in various countries of the world" | OK |
| Tab. comparação, col. C, I = – | — | §IX-A (p. 18) | "To guarantee them, MQTT (as well as MQTT-A) should be used over TLS/SSL" | OK (–): delega no TLS por salto; dizê-lo no texto |

## Revisões relacionadas (Secção 4, Tab. revisões)

| Revisão | Onde | Afirmação | Localização | Excerto | Estado |
|---|---|---|---|---|---|
| Perrone et al. 2017 `perrone2017mirai` (scitepress, 6 pp.) | 04:9 | Escrito após a Mirai; levantamento "conciso e não exaustivo" | Título e Resumo (p. 1) | "The Day After Mirai"; "a concise, though not exhaustive, survey" | OK |
| Nebbione e Calzarossa 2020 `nebbione2020security` (Future Internet 12(3), 55) | 04:13 | Segurança dos protocolos da camada de aplicação; CVE; boas práticas | Resumo (p. 1); §1 (p. 2) | "The main threats of these protocols as well as the Common Vulnerabilities and Exposures (CVE) [...] Good practices and measures" | OK |
| idem | Tab. revisões "Protocolo RSL" = – | — | §3 (p. 5) | "we searched numerous websites and popular digital libraries and databases, such as ACM, IEEE, Springer, Google Scholar, Scopus" | OK (–): indica fontes, mas sem *strings* nem critérios |
| Hintaw et al. 2023 `hintaw2023mqtt` (IETE J. Res. 69(6), pp. 3368–3397; publicado *online* em 2021). **O PDF disponível está incompleto: só a capa, a 1.ª página (resumo e início da introdução) e as biografias dos autores.** Só o resumo é verificável | 04:16; 02-enquadramento (STRIDE) | DoS, *spoofing*, divulgação, elevação de privilégios, adulteração; custo em dispositivos a bateria | Resumo (p. 1) | "Some of the issues are denial of service, identity spoofing, information disclosure, elevation of privileges and data tampering"; "will have a bearing on IoT devices that are powered by a battery" | OK (cinco das seis categorias STRIDE: falta o repúdio) |
| Lakshminarayana et al. 2024 `lakshminarayana2024securing` (IEEE COMST 26(4), pp. 2510–2546; p. *n* = 2509+*n*) | 04:20 | Classificam vulnerabilidades e ataques; discutem defesas; ênfase em deteção | Index Terms (p. 1); §I (p. 3); Tab. V–VII (pp. 18, 22, 25) | "vulnerability taxonomy for the MQTT protocol"; Index Terms: "taxonomy, testing, detection, defense" | OK |
| idem | Tab. revisões "Compara por propriedade" = – | — | Tab. VII (p. 25): colunas *Techniques used / MQTT Version / Strengths / Limitations*; Tab. IV (p. 12) cruza vulnerabilidades com requisitos | — | OK (–): compara por pontos fortes e fracos, não por propriedade |
| Laghari et al. 2024 `laghari2024securing` (IEEE Access 12, pp. 139273–139289) | 04:23 | Taxonomia de ataques ao ecossistema; revisões anteriores "amplas mas superficiais" | Resumo (p. 1); §III, Fig. 6 (p. 5) | "a broad but superficial discussion of MQTT attacks and countermeasures"; "a comprehensive taxonomy of security attacks within the MQTT ecosystem" | OK |
| idem | Tab. revisões "Protocolo RSL" = – | — | §I (p. 2) | "we initially identified 629 articles from Google Scholar, 19 from Web of Science, and 22 from Scopus from 2018 to 2023 using the keyword 'MQTT Security'. We then included only review/survey papers written in English, excluding duplicates, three papers due to their superficial discussion [...]" | CORRIGIDO → ● (pesquisa e seleção explícitas, mas só para as revisões relacionadas e com uma única palavra-chave) |

## Correções da revisão final (01-11-2026)

| Onde | Afirmação | Fonte e localização | Estado |
|---|---|---|---|
| 01-introducao (Mosquitto) | "tornaram o protocolo omnipresente" | `light2017mosquitto`, Resumo: "standards compliant server and client implementations" | CORRIGIDO → "implementações abertas e conformes à norma" |
| 01-introducao (TLS) | "recomenda TLS" | `oasis-mqtt311` §5: "This is commonly achieved by using TLS" | CORRIGIDO → "tipicamente com TLS" |
| 01-introducao (P1) | subscrição de `#` | `oasis-mqtt311` §4.7.1.2 e §4.7.2 (tópicos `$` excluídos); `segarra2020mqttz` Resumo ("process data in clear") | CORRIGIDO; retirada a citação de Andy |
| 02 (AES-GCM) | "a AEAD mais usada" | não sustentado pelo SP 800-38D | CORRIGIDO → "normalizada pelo NIST" |
| 02 (retenção) | o *broker* guarda a última mensagem | `oasis-mqtt311` §3.3.1.3: "the Server MUST store the Application Message" | OK, citação acrescentada |
| 02, Tab. 1 | palavra-passe em claro | `oasis-mqtt311` §5.4.1: "passing authentication data in clear text" | OK, citação acrescentada |
| 02, Tab. 1 | AUTH desafio–resposta | `oasis-mqtt5` §4.12: "challenge / response style authentication" | OK, citação acrescentada |
| 05 (QF1) | "brokers mal configurados" (Andy) | Resumo de Andy: "by default, does not encrypt the data in transit" | CORRIGIDO → "sem cifra, por omissão" |
| 05 / Anexo B | Hernández "baseada em modelos" | Resumo: "template-based fuzzing technique" | CORRIGIDO → "baseada em *templates*" |
| 04, Tab. revisões | Hintaw "Taxonomia de ataques ✓" | só o resumo está acessível (lista 5 classes) | CORRIGIDO → ●, com nota |
| 07 | "muitos dispositivos IoT não têm AES em hardware" | `sadio2019lightweight` Resumo: "constrained nodes processors did not have hardware support for AES" | OK, citação acrescentada |
| 07 | H1 5,4 µs; H3 205 µs | medições da máquina de desenvolvimento (`docs/benchmarks.md`), incompatíveis com um relatório teórico | RETIRADO; hipóteses qualitativas |
| 03 (*string*) | "a leitura das revisões levou a incluir MQTT-SN e *intrusion*" | sem registo do processo | CORRIGIDO → só a justificação técnica |
| 03 (leitura) | "três passagens de Keshav", "formulário fixo" | não foi o método seguido | CORRIGIDO → leitura integral orientada aos itens de extração, com rastreabilidade |
| 03, 08, PRISMA | seleção "intencional para cobrir as categorias" | critério reconstruído depois | CORRIGIDO → estudos de uma fase exploratória, todos elegíveis na triagem, sem critério *a priori* |
| 03 (CE2) | MQTT-Auth em conferência "excluído" | R0108 marcado I na triagem; Calabretta et al. §I (p. 2): "whose preliminary version was presented in [8]" | CORRIGIDO → elegível, analisada só a versão alargada |
| 05 (QF4) | "as métricas mais comuns são latência, memória e *overhead*" | nunca contado | RETIRADO |
| 02 (*token bucket*, Eq. 4) | taxa ρ, rajada β, acumulação até ao máximo | `rfc2697` §3 "Metering": "the token counts Tc and Te are updated CIR times per second [...] If Tc is less than CBS, Tc is incremented by one"; "If Tc(t)-B >= 0, the packet is green and Tc is decremented by B" | ACRESCENTADO (a RFC conta octetos; o relatório conta mensagens, dito no texto) |
| 02 (STRIDE) | as seis categorias | `kohnfelder1999threats` (Microsoft Interface, 1/4/1999, cópia arquivada): "S.T.R.I.D.E. stands for: Spoofing of user identity, Tampering with data, Repudiability, Information disclosure (privacy breach), Denial of Service (D.o.S.), Elevation of privilege" | ACRESCENTADO |
| 02 (limites da proteção) | o tópico segue no cabeçalho variável do PUBLISH, visível ao *broker* | `oasis-mqtt311` §3.3.2.1: "The Topic Name MUST be present as the first field in the PUBLISH Packet Variable header" | ACRESCENTADO |
| 06 (§6.9, limites no *broker*) | o SlowITe esgota as ligações do *broker* | `vaccari2020slowite` §4: "SlowITe must seize all available connections" | ACRESCENTADO |
| 07 (Tab. de ataques) | ocupação de ligações | `vaccari2020slowite` §4 | ACRESCENTADO; as restantes linhas são expectativas do desenho, não afirmações de fontes |
| 06 (§6.4, ChaCha20) | *nonce* de 96 bits e etiqueta de 128 bits, como no AES-GCM | `rfc8439` §2.8 ("A 96-bit nonce") e §2.5 ("The output is a 128-bit tag") | ACRESCENTADO; o algoritmo como atributo da chave é decisão de desenho |
| 07 (K11, casos de uso, artefacto) | — | decisões do plano, sem afirmações de fontes | ACRESCENTADO |

## Correções da revisão independente e da revisão cética (01-11-2026)

| Onde | Afirmação ou célula | Fonte e localização | Estado |
|---|---|---|---|
| 03 §3.5, PRISMA, `dados-revisao.tex` | Andy et al. e Hernández Ramos et al. estavam incluídos, mas só se tinha lido o resumo | Anexo B anterior: "Só o resumo" | CORRIGIDO → excluídos por CI4 (texto integral não obtido); 17 estudos, renumerados E01–E17 |
| 03 Tab. critérios | CI4 "o texto integral está acessível" | o texto de Hernández é de acesso aberto; o critério aplicado foi «obtido» | CORRIGIDO → "O texto integral foi obtido" |
| 03 PRISMA | elegíveis e procurados na mesma caixa; Lohachab "excluído" | PRISMA 2020 (`page2021prisma`), caixas *reports sought / not retrieved* | CORRIGIDO → caixas separadas: 721 elegíveis; 701 não avaliados; 20 procurados; 3 não obtidos; 17 incluídos; excluídos por critério (CE1 1081, CI1 535, CE4 85, CE6 25, CE3 3) a partir de `dados/decisoes-triagem.csv` |
| 03 PRISMA | revisões: "73 da *string* secundária; 1 por *snowballing*" | `dados/revisoes-decisoes.csv`: Perrone V0006/R0091, Nebbione V0017, Laghari R1463, Lakshminarayana R1469 | CORRIGIDO → 2 da secundária (1 também da principal), 2 da principal (CE4), 1 por *snowballing* |
| 03 §3.3, 08 Tab. validade | redução da *string* no ScienceDirect e campo *All Metadata* no IEEE não declarados | Anexo A (as próprias *strings*) | ACRESCENTADO |
| 03 §3.5, 05 Tab. qualidade | não havia avaliação da qualidade | critérios QA1–QA5; pontuação por estudo a partir do texto integral (ver tabela seguinte) | ACRESCENTADO |
| 04 | seleção das revisões sem critério | `dados/revisoes-decisoes.csv` (121 candidatas; RV1, RV2; título e resumo) | ACRESCENTADO: 21 excluídas por RV1, 79 por RV2; 21 cumprem, 4 analisadas, 17 não analisadas (falta de tempo, declarado) |
| 04 | "Só Laghari et al. descrevem a pesquisa e a seleção" | `nebbione2020security` fim da §3 (p. 5): "we searched numerous websites and popular digital libraries and databases, such as ACM, IEEE, Springer, Google Scholar, Scopus"; `lakshminarayana2024securing` §I (p. 3): "we present a systematic review of the MQTT protocol" | CORRIGIDO → nenhuma relata um protocolo completo; descrição de cada uma |
| 05 Tab. comparação, E03 Au | Nr | `rizzardi2016aups` Resumo; título "AUthenticated Publish&Subscribe"; §III: "external applications, which authenticate to NOS" | CORRIGIDO → ✓ |
| 05 Tab. comparação, E03 BnC | Nr | `rizzardi2016aups` §IV, passos 5–7 (p. 9): "NOS encrypts the data d with the obtained keyT, thus obtaining the encrypted data denc"; o *broker* só recebe `denc` | CORRIGIDO → ✓ |
| 05 Tab. comparação e Tab. proposta, E04 I | Nr | `calabretta2018mqttauth` §IV-A: o *broker* entrega os dados cifrando-os "using an authenticated encryption (AE) algorithm" | CORRIGIDO → ● (integridade por salto) |
| 05 Tab. comparação e Tab. proposta, E05 BnC | ver a linha de E05 acima | `dinculeana2019vulnerabilities` §5 (p. 7) | CORRIGIDO → ✓ |
| 05 Tab. comparação e Tab. proposta, E06 P | ✓ | `malina2019secure` §5.2: a privacidade é do SL2 ("SL2 enhances the privacy protection") | CORRIGIDO → ● (só num nível, como C) |
| 05 Tab. comparação e Tab. proposta, E14 P | ✓ | `vanglabbeek2022flexible` §3.2 e §4.3: anonimato e não ligação só na opção 3 | CORRIGIDO → ● (só numa opção, como C) |
| 05 Tab. comparação e Tab. proposta, E17 P | Nr | `javadi2026cmap` §V-A2 "Traceability attack": valores aleatórios novos em cada sessão | CORRIGIDO → ● (só na autenticação) |
| 05 Tab. comparação, E12 I | Nr | `spielvogel2021tls` §II: os níveis de segurança protegem "confidentiality and integrity" por salto | CORRIGIDO → ● (como C) |
| 05 Tab. comparação, E15 BnC | Nr | `buccafurri2023mqtta` §IX: o *broker* público é adversário para efeitos de anonimato | CORRIGIDO → ● |
| 05 Fig. propriedades e texto | C 12, Az 7, Au 7, I 7; BnC 4 de 16 | recontagem da Tab. comparação | CORRIGIDO → C 12 (8 total, 4 parcial), I 9, Au 8, Az 7; BnC 7 (4 total, 3 parcial); P 4 |
| 05 C5 (Malina) | "Nos níveis 2 e 3 o carimbo serve de proteção contra repetição" | `malina2019secure` §4.5 (SL1): "t is an actual timestamp [...] that prevents replay attacks" | CORRIGIDO → em todos os níveis |
| 05 QF4 | "só um apresenta uma prova formal" | `singh2015secure` §VI: Lemas 1–3 com "Proof" que remete para os esquemas ABE de [7], [8] | CORRIGIDO → mantém-se a prova formal só em Javadi; Singh enuncia lemas sem prova própria |
| 05 QF1 | Andy e Hernández | excluídos | CORRIGIDO → `vaccari2020slowite`, `segarra2020mqttz`, `dahlmanns2021entrust`, `spielvogel2021tls`; `vaccari2020mqttset` §3.1 (ataques: inundação, *publish flood*, SlowITe, dados malformados, força bruta); `alotaibi2024secure` §2.4 (fases do ataque ao *broker*) |
| 05 QF5 | respondida com Hintaw (revisão) | limitações declaradas (Anexo B): `dinculeana2019vulnerabilities` §6; `sadio2019lightweight` §V; `buccafurri2023mqtta` §VIII ("This is the main drawback of the proposed approach"); `segarra2020mqttz` §VI ("all clients are serialized", limitação do OP-TEE); `vanglabbeek2022flexible` §7 ("Currently, the architecture relies on a semi-trusted broker and a fully trusted CA") | CORRIGIDO |
| 05 QE1 | "cresce de forma contínua" | Fig. 3: 58→51 (2020), 74→66 (2022), 115→101 (2025) | CORRIGIDO → "tendência crescente, com descidas pontuais" |
| 06 Tab. proposta, linha Proposta | C ✓, NR ✓ | §6.4: os modos são alternativos | CORRIGIDO → ●, com nota |
| 06 Tab. proposta, E12 Spielvogel | não estava na tabela | `spielvogel2021tls` Resumo: publicadores e subscritores exigem um nível mínimo, aplicado pelo *broker* | ACRESCENTADO (RN ●) |
| 06 §6.6 | w = 64, Δa, Δs sem justificação | `rfc4303` §3.4.3 ("a window size of 64 [...] SHOULD be employed as the default") | CITADO; Δa e Δs declarados como valores iniciais |
| 06 §6.4 | tamanhos dos campos do cabeçalho | decisão de desenho (2+1+1+4+8+8+1 = 25) | ACRESCENTADO |
| 07 Eq. custo | divisão por zero (octetos acrescentados em K0); débito invertido | — | CORRIGIDO → razão invertida para métricas «maior é melhor»; octetos totais; S_max definido |
| 07 Tab. configurações, K9 | "+ não repúdio" | §6.4: o modo de assinatura deixa o conteúdo legível | CORRIGIDO → "troca a confidencialidade face ao *broker* pelo não repúdio" |
| 08 L2 | "Nenhum dos estudos analisados aplica [...] restrição [...] nem política" | `dahlmanns2021entrust` §5.2–5.3; `malina2019secure` §4.5 (p. 6, o pedido de subscrição leva o nível: "send the broker (B) the subscribe request that contains the name of the security level") e §4.6–4.7; `spielvogel2021tls` Resumo | CORRIGIDO → aparecem em parte, nunca aplicadas no próprio recetor |
| 08 L3, Resumo, Conclusões | "só quatro"; "a maioria das soluções confia no *broker*" | recontagem da Tab. comparação | CORRIGIDO → sete (4 total, 3 parcial); nove dos 16 não dispensam |
| 08 L4 | "As restantes soluções usam segredos partilhados" | `singh2015secure` (ABE, cifra sem autenticação de origem); `javadi2026cmap` (autentica a ligação) | CORRIGIDO → restrito às que protegem a mensagem, com as duas exceções |
| 09 | "nunca combinados" | `malina2019secure` combina carimbo, tópico assinado e não repúdio | CORRIGIDO → "nenhum combina a validade temporal com a deteção de duplicados" |
| 00 Resumo | "o TLS não impede a repetição" | `rfc8446` §5.3 (números de sequência por registo) | CORRIGIDO → "não impede que uma mensagem válida seja repetida ao nível da aplicação, pelo *broker* ou por um cliente" |
| 02 §2.5 | `rfc2697` §3 citado para o balde único | `rfc2697` §3 define o srTCM (dois baldes, marcação por cores) | CORRIGIDO → "com a regra de reposição do balde C do srTCM" |

### Células da Tab. comparação que não tinham linha própria (acrescentadas em 01-11-2026)

| ID e coluna | Localização | Excerto | Estado |
|---|---|---|---|
| E01 C = ✓ | Resumo (p. 1); §III-B | KP/CP-ABE: só subscritores com atributos compatíveis decifram | OK |
| E02 Au = ✓ | §III-C "MQTT Broker Authentication" | o dispositivo liga-se ao *broker* com o *token* de acesso e as credenciais, em vez do nome de utilizador e da palavra-passe habituais (Tab. III) | CORRIGIDO → ✓ (antes ●) |
| E02 Az = ✓ | §I | "In this paper we introduce a new authorization mechanism for MQTT-based IoT devices" | OK |
| E03 C = ✓ | §IV, passo 5 (p. 9) | "NOS encrypts the data d with the obtained keyT [...] where any existing encryption mechanism enc(·) can be used" | CORRIGIDO → ✓ (antes ●, sem linha que o justificasse; a cifra é genérica, mas a confidencialidade face ao *broker* é garantida por desenho) |
| E04 C, Au, Az = ✓ | Resumo (p. 1); §IV, Eq. 10–12 | linha descritiva de E04 acima ("AugPAKE [...] for guaranteeing confidentiality, and onto two tokens") | OK |
| E05 C, I = ✓ | Resumo (p. 1) | linha descritiva de E05 acima ("ensuring the confidentiality and integrity of information through the use of one mechanism") | OK |
| E07 C, I = ✓ | Resumo; §IV-A | ChaCha20-Poly1305 é uma AEAD (`rfc8439` §2.8); "MQTT Broker and other unauthorized entities cannot read the message content" | OK |
| E09 D = ● | Resumo; §3.2 | conjunto de dados para treinar detetores (deteção, não prevenção) | OK |
| E10 C, Au = ✓ | Resumo (p. 1) | "a mutual TLS-based handshake and a two-layer encryption for end-to-end security" | OK |
| E10 BnC = ● | Resumo (p. 1) | "using the TEE as a trusted proxy": dispensa a confiança no SO do *broker*, mas não no TEE | OK |
| E11 BnC = ✓ | §6 (p. 7) | "moving trust from the broker [...] to a key server" | OK |
| E12 C, I = ● | §II | os níveis de segurança por salto protegem "confidentiality and integrity" só nas ligações que os cumprem | OK |
| E12 BnC = ✗ | §II-B "Trust assumptions"; Fig. 2 | "trust the broker to process the messages correctly"; "Trusted enhanced broker enforces publisher's security" | OK |
| E13 C, I = ✓; BnC = ✗ | §4 (p. 3) | "TLS 1.2" por salto: C e I em cada ligação, terminando no *broker* (`rfc8446` §1) | OK |
| E15 P = ✓ | Resumo (p. 1) | linha descritiva de E15 acima (anonimato de origem e destino) | OK |
| E16 D = ● | Resumo; §4.5 | deteção de anomalias (deteção, não prevenção) | OK |
| E17 Au = ✓ | Resumo (p. 1) | "the Certificateless MQTT-based Authentication Protocol (CMAP), a lightweight mutual authentication protocol" | OK |
| E01 BnC = ● | §III-B; §VI; §VII-A | "Broker (trusted third party) renders the function of a PKG"; "In case of Broker hijacking, message confidentiality is assured [...] any malicious Broker cannot decrypt ciphertext"; "PKG and Broker are separate entities but in the current implementation they are the same" | CORRIGIDO → ● (antes ✗): o artigo é ambíguo; nota no texto |
| E04 I = ✓ | §IV-A | a mesma cifra autenticada por salto que dá C ✓ ("using an authenticated encryption (AE) algorithm") | CORRIGIDO → ✓ (antes ●, incoerente com C) |
| E05 Au = ✗ | §6 (p. 8) | "Additional mechanisms need to be implemented to deal with client authentication, key distribution [...] and replay attacks" | CORRIGIDO → ✗ (antes –; coerente com R = ✗) |
| E07 Au = ✓ | §IV-A | o recetor decifra "then verify the authenticity of data" (AEAD com chave partilhada, como E11) | CORRIGIDO → ✓ (antes –) |
| E10 Restr. = ✓ | §IV; §VI-C | "Raspberry Pi 3 Model B units" | CORRIGIDO → ✓ (antes –; o Raspberry Pi conta como restrito em E03, E14, E17) |
| E12 Au = ● | §II | os níveis de segurança por salto incluem "authentication, confidentiality and integrity" | CORRIGIDO → ● (antes –; coerente com C e I) |
| E12 Restr. = ✓ | §I; §II-C | "a Wemos D1 mini with the ESP8266EX chip running at 80/160MHz and only 50kB" | CORRIGIDO → ✓ (antes –) |
| E14 Az = ● | §3.1 | "the devices, together with their topics of interest and topics on which they publish, are registered at the CA" | CORRIGIDO → ● (antes –) |
| Tab. proposta, E14 LT = ✓ | §4.3 | assinatura Schnorr sobre M‖T‖ID_G (o tópico T entra na assinatura, como em E06) | CORRIGIDO → ✓ (antes –) |
| Tab. proposta, E04 CT = ● | §IV-A | "only the creator of a certain topic, by means of Auth1, is allowed to write on that particular topic at the broker" | CORRIGIDO → ● (antes –; aplicado no *broker*) |
| Tab. proposta, E06 CT = ● | §4.4 | "the database server which stores publishers' ID and topics. This database also serves as the whitelist for B" | CORRIGIDO → ● (antes –; aplicado no *broker*) |
| Tab. proposta, Proposta Au = ● | §6.11 | nos modos AES, as ordens usam uma chave de grupo | CORRIGIDO → ● (antes ✓) |

### Correções da segunda revisão independente e cética (01-11-2026)

| Onde | Correção | Fonte |
|---|---|---|
| `dados-revisao.tex`, PRISMA, Fig. 3 | 5 pares com o mesmo título e DOI diferente marcados como duplicados (D) em `dados/decisoes-triagem.csv`: 2445 triados, 1726 excluídos (CE1 1079, CE6 24), 719 elegíveis; 2017 = 16, 2022 = 65; 2023–2026 = 57,0 % | `dados/decisoes-triagem.csv` (R0052, R0067, R0144, R0903, R0972) |
| PRISMA | versão preliminar de E04 (R0108) excluída por CE2 numa caixa própria; 698 não avaliados | §3.4 do relatório; `calabretta2018mqttauth` §I |
| Anexo A, §3.3 | o filtro de tipo foi aplicado pelo *script*, não na exportação; inclui livros | `dados/registos.csv`: 11 *IEEE Standards*, 9 *Magazines*, 16 *eBooks*/capítulos IEEE, 4 `incollection` ScienceDirect |
| Resumo, L3, Conclusões | "nove dos 16 não dispensam" → "em oito dos 16 a confiança é assumida (cinco) ou não é tratada (três)" | recontagem da Tab. comparação, com E01 BnC = ● |
| L5, Conclusões | exceção parcial: relação analítica entre latência e resistência a *brokers* maliciosos | `buccafurri2023mqtta` §VIII-C: "we report explicitly the tradeoff between security and efficiency" |
| Resumo, Conclusões | "nunca a validade temporal com a deteção de duplicados" limitado às mensagens publicadas | `niruntasukrat2016authorization` §V-C (carimbo e *nonce* no pedido de autorização) |
| §2.3 | "a AEAD normalizada pelo NIST" → "uma AEAD" | o NIST normaliza também o CCM (SP 800-38C) |
| §2.4, §6.6, §7.5 | notação: Δ_id e Δ_rel; pesos ω_a; benefício π_a; "se e só se"; reordenação até w−1 | Eq. 3 |
| §6.4 | geração do *nonce* (aleatório, 96 bits) e rotação antes de 2^32 | `nist-sp800-38d` §8.3 |
| §6.7 | exemplo da Eq. 9 (`sensors/%u/#`) e `%k ↦ id(k)` | — |
| §5.2.7 | Alotaibi: objetivo de tempo real; avaliação sobre o MQTTset | `alotaibi2024secure` §4.1: "This research is conducted using the MQTTset data set" |
| §5.2.5 | Malina, o *broker* decifra: §4.6–4.7 | `malina2019secure` §4.7: "B decrypts the ciphertext encrypted by AES-GCM" |
| Tab. qualidade | E01 QA2, E04 QA3, E05 QA1, E07 QA3 e QA5, E09 QA3, E13 QA5, E16 QA3 (ver tabela seguinte); média 3,5 | — |
| Bibliografia | estilo `IEEEtran-pt.bst` (termos em português); autores do repositório; ano de Kohnfelder repetido | — |

Fontes que não estão em `rsl/textos/` (13 dos 22 PDFs estão): Dahlmanns, Prantl, Segarra, Spielvogel, Van Glabbeek, SlowITe, MQTTset e Alotaibi foram lidos nas versões indicadas no Anexo B (cópia de autor, SPEC, arXiv, PubMed Central).

### Avaliação da qualidade (Tab. qualidade): fundamento de cada pontuação

Textos usados: `rsl/textos/` e, para Dahlmanns, Prantl, Segarra, Spielvogel, Van Glabbeek, SlowITe, MQTTset e Alotaibi, as cópias de autor, arXiv ou PMC indicadas no Anexo B.

| ID | QA1 modelo de ameaças | QA2 avaliação | QA3 referência | QA4 artefacto | QA5 limitações |
|---|---|---|---|---|---|
| E01 Singh | 0,5: PKG/*broker* de confiança (§III-B); lemas CPA, MITM, conluio (§VI) | 1: implementação com Paho e Mosquitto em três portáteis (§VII-A) | 1: "compare the performance of SMQTT [...] and technique described in [3]" (§VII) | 0 | 0,5: "As part of our future work" (conclusão) |
| E02 Niruntasukrat | 0,5: pressupostos ("we assume IoT devices have no special ID", §III) | 1: Arduino Mega e outros (§IV) | 0,5: comparação qualitativa com Fremantle et al.; "quantitative benchmark is not possible" (§IV) | 0 | 0,5: "For future work, [...] application-level data encryption" (§VI) |
| E03 Rizzardi | 0,5: análise de robustez a ataques (§IV-A), sem modelo próprio | 1: Raspberry Pi (§V) | 0,5: comparação qualitativa com o SecKit (§IV-A) | 1: "released as open source under Apache v.2 license" (Resumo) | 0,5: "Future extensions include testing in a larger, more complex" (§VI) |
| E04 Calabretta | 0,5: "the broker should be considered as a trusted entity" (§IV-A) | 1: dois *testbeds* (§V) | 1: Tab. IV, n.º de mensagens para estabelecer a chave de sessão face a [21] (§V) | 1: "its source code is available at the project web page" (§V) | 0,5: "Some possible future developments" (§VI) |
| E05 Dinculeană | 0,5: enumera ataques (tabelas *rainbow* §3.2; DoS e repetição §6), sem capacidades do adversário | 1: Onion Omega2+ (§3.1) | 1: face a cifra simétrica (§5) | 0 | 1: "Additional mechanisms need to be implemented [...]" (§6) |
| E06 Malina | 0,5: "It is assumed that the public keys of the broker [...]" e outros pressupostos (§4.3–4.4) | 0,5: contagem de operações (§5.1) | 1: "Table 2: Performance Comparison of Our Solution and Related Works" | 0 | 0: a conclusão não declara limitações |
| E07 Sadio | 0 | 1: Arduino UNO (§IV-B) | 1: memória "when AEAD is applied and not applied" (§IV-B, Fig. 4) | 0: só bibliotecas de terceiros | 1: "needs a best secret key management when the number of nodes increases" (§V) |
| E08 SlowITe | 0,5: o ataque e as capacidades do atacante (§4) | 1: serviços reais (§5) | 1: com e sem TLS, em quatro *brokers* (§5.2) | 0 | 0,5: "Further work may be directed on a refinement of SlowITe" (§7) |
| E09 MQTTset | 0,5: ataques incluídos no conjunto (§3.1) | 1: detetores treinados (§4) | 0,5: algoritmos comparados entre si; comparação com outros conjuntos só qualitativa (Tab. 1) | 1: kaggle.com/cnrieiit/mqttset (§6) | 0,5: "Future work will be related to the application and validation of this dataset" (§5) |
| E10 Segarra | 1: "Threat Model" (§IV) | 1: Raspberry Pi 3B (§VI) | 1: REE vs TEE (§VI) | 1: "We release MQT-TZ as open-source" (§I) | 1: OP-TEE "all clients are serialized" (§VI) |
| E11 Dahlmanns | 1: "Attack Vectors in PubSub Communication": clientes que se ligam e publicam ou subscrevem; *brokers* maliciosos ou comprometidos (§3.1) | 1: RedBear Duo (§7) | 1: "comparing the computation runtime of ENTRUST to a baseline" (§7) | 0 | 0,5: "For future work we envision to further improve the performance" (conclusão) |
| E12 Spielvogel | 0,5: o que o atacante revela; *broker* honesto (§II) | 1: protótipo (§V) | 1: "in comparison to a non-secured connection" (§II-C) | 0 | 1: "this is only a prototype" (§V); topologia física e VPN deixadas a trabalho futuro (§IV, §VI) |
| E13 Prantl | 0: estudo de desempenho | 1: ESP8266 (§4) | 1: medições com e sem TLS | 1: github.com/WueSePrantl/MQTT_TLS_Performance | 1: §6.3 "Threats to Validity": um só cliente, exatidão das medições, só MQTT |
| E14 Van Glabbeek | 1: "Dolev-Yao security model" (§3.1) | 1: Raspberry Pi (§6) | 1: face ao MQTTS (§6) | 1: github.com/tperale/distmqtt (§6) | 1: "Currently, the architecture relies on a semi-trusted broker and a fully trusted CA" (§7) |
| E15 Buccafurri | 1: "IX. Threat Model and Security Analysis" | 1: *brokers* em nuvem (§VIII) | 1: "comparing MQTT-A with standard MQTT" (§I, §VIII) | 0 | 1: "This is the main drawback of the proposed approach" (§VIII) |
| E16 Alotaibi | 0,5: fases do ataque descritas (§2.4) | 1: (§4) | 0,5: algoritmos H2O comparados entre si; comparação com outros trabalhos só qualitativa | 0 | 0: a conclusão não declara limitações |
| E17 Javadi | 1: "Dolev-Yao model [...] active adversary" (§V) | 1: Raspberry Pi e NS-3 (§VI) | 1: face ao TLS (338 vs 713 ms) | 1: "We make the CMAP code publicly available" (§I) | 0,5: direções de investigação futura (§VII) |

## Normas, RFC e primitivas

| Onde | Afirmação | Fonte e localização | Excerto | Estado |
|---|---|---|---|---|
| 01-introducao.tex:7 | MQTT normalizado pela OASIS nas versões 3.1.1 e 5.0 | `oasis-mqtt311`, `oasis-mqtt5`, página de título | — | OK |
| 01-introducao.tex:7 | "o protocolo de mensagens mais usado na IoT" | nenhuma fonte o mede | — | CORRIGIDO → "um dos mais usados", citando Van Glabbeek §1 ("currently one of the most popular application protocols in Internet of Things") ou Alotaibi, Resumo |
| 02-enquadramento.tex:9 | Transporte ordenado e fiável; portas 1883/8883 | `oasis-mqtt311` §1 Introdução ("ordered, lossless, bi-directional connections") e §4.2 Network Connections (comentário não normativo: "TCP ports 8883 and 1883 are registered with IANA") | ver coluna anterior | OK |
| 02-enquadramento.tex (QoS) | QoS 0/1/2: no máximo uma vez, pelo menos uma vez, exatamente uma vez | `oasis-mqtt311` §4.3.1–4.3.3; `oasis-mqtt5` §4.3.1–4.3.3 | "QoS 1: At least once delivery" | CITADO |
| 02-enquadramento.tex (filtros) | Curingas `+` e `#`; tópicos `$` | `oasis-mqtt311` §4.7.1.2, §4.7.1.3, §4.7.2 | "The multi-level wildcard character MUST be specified either on its own or following a topic level separator" | CITADO |
| 06-proposta.tex (QoS 1) | A marca DUP só indica um possível reenvio | `oasis-mqtt311` §3.3.1.1 | "If the DUP flag is set to 1, it indicates that this might be re-delivery of an earlier attempt to send the Packet" | OK |
| 01-introducao.tex:23; 02-enquadramento.tex:81 | O TLS protege cada salto cliente–*broker* | `rfc8446` §1 (canal entre dois pares) | "The primary goal of TLS is to provide a secure channel between two communicating peers" | OK |
| 02-enquadramento.tex:122–128 | Com nonces aleatórios, o NIST limita a 2^32 as invocações por chave | `nist-sp800-38d` §8.3 (p. 21) | "The total number of invocations of the authenticated encryption function shall not exceed 2^32" (aplica-se à construção RBG, ou seja, IV aleatório) | OK |
| 02-enquadramento.tex:127 | (removido) Probabilidade de colisão ≈ q²/2^97 | derivação própria, não estava no SP 800-38D | — | REMOVIDO; a frase cita agora só o §8.3 |
| 02-enquadramento.tex:125 | Reutilizar (K, N) permite falsificar etiquetas | `bock2016nonce` (USENIX WOOT'16), Resumo e §2 ("forbidden attack") | — | SEM ACESSO (confirmar a secção) |
| 02-enquadramento.tex:131 | O HMAC não prova a origem | `rfc2104` Resumo | "in combination with a secret shared key" | OK |
| 02-enquadramento.tex:133 | Assinatura Ed25519 de 64 octetos | `bernstein2012ed25519` p. 1 ("signatures are 64 bytes"); `rfc8032` §5.1 ("signatures are 64 octets") | ver coluna anterior | OK |
| 02-enquadramento.tex:151 | Janela anti-repetição do ESP; 64 é o valor recomendado | `rfc4303` §3.4.3 | "a window size of 64 is preferred and SHOULD be employed as the default" | OK |
| 02-enquadramento.tex (estado só depois da autenticação) | — | `rfc4303` §3.4.3 | "The receive window is updated only if the integrity verification succeeds" | CITADO |
| 02-enquadramento.tex:128; 07-plano:74 | ChaCha20-Poly1305 como alternativa sem AES em *hardware* | `rfc8439` §1 | — | OK |

---

## Pendentes

- `lohachab2019ecc`, `andy2017attack`, `hernandez2018fuzzing`: excluídos por CI4 (texto integral não obtido); só são citados na Secção 3.5, como excluídos.
- `bock2016nonce`: sem acesso ao texto integral; a afirmação usada (reutilizar (K, N) permite falsificar etiquetas) está no resumo.
- `kitchenham2007`, `page2021prisma`: citados pelo método, sem afirmação a localizar.
