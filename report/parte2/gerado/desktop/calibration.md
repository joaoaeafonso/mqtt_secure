# Calibração de Δa e Δs (desktop-20261115)

Relatório §6.6: os valores iniciais (Δa = 60 s, Δs = 5 s) são calibrados a partir da latência medida e do desvio de relógio observado. Pior caso legítimo em todas as execuções de custo e nos pontos de saturação sustentados (perda < 1 %, p99 ≤ L_max), multiplicado por 2 e arredondado para cima a 100 ms.

- latência máxima: 68.679 ms (p99,9 máximo: 52.360 ms)
- desvio de relógio dos agentes |offset| máximo: 0.055 ms; incerteza residual após correção: 0.219 ms

| | Δs (ms) | Δa (ms) |
|---|---|---|
| relógios sem correção (Δs cobre o offset) | 100 | 200 |
| relógios sincronizados (resta a incerteza) | 100 | 200 |

Usar a linha que corresponde ao cenário de implantação (dispositivos com NTP/PTP ou não). Valores por omissão por fluxo: ver `FreshnessRule`.
