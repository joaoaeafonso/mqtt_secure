# Relatório — Projeto, Parte 2 (SRSI)

Implementação, medições e validação da arquitetura proposta na Parte 1
(`../main.tex`). Usa o preâmbulo, as figuras e a bibliografia da Parte 1.

## Compilar

```bash
make dados PI=pi5-<data> DESKTOP=desktop-<data>   # depois de tools/analysis/analyze.py
make                                             # => main.pdf
```

Sem dados em `gerado/`, o relatório compila na mesma: cada tabela ou figura em
falta aparece como uma caixa com o nome do ficheiro esperado.

## Como está organizado

| Ficheiro | Conteúdo | Estado |
|---|---|---|
| `seccoes/01-introducao.tex` | objetivo, perguntas QP1–QP5, o que mudou face ao plano | texto escrito |
| `seccoes/02-prototipo.tex` | o que foi implementado e onde (critério "implementação") | texto escrito; rever |
| `seccoes/03-metodo.tex` | plataforma, configurações, métricas, ataques, procedimento, parâmetros fixados | texto escrito; falta a plataforma e R_alvo/L_max |
| `seccoes/04-custo.tex` | QP1, QP3, QP4: tabelas e figuras geradas | à espera dos dados |
| `seccoes/05-protecao.tex` | QP2: matriz de ataques, cenários com controlo negativo | à espera dos dados |
| `seccoes/06-criterio.tex` | QP5: S(c), custo(c), Pareto, c* por caso de uso | à espera dos dados |
| `seccoes/07-hipoteses.tex` | veredicto de H1–H5 | à espera dos dados |
| `seccoes/08-validacao.tex` | testes, cenários, calibração de Δa e Δs, reinício do recetor | parte escrita |
| `seccoes/09-ameacas.tex` | ameaças à validade e limitações | texto escrito |
| `seccoes/10-conclusoes.tex` | conclusões | à espera dos dados |
| `seccoes/anexo-a-reproducao.tex` | como reproduzir; plataforma de referência | texto escrito |

O que falta escrever está marcado com `\PorFazer{...}` (a vermelho no PDF):
`grep -n PorFazer seccoes/*.tex` dá a lista.

## Regras

- Nenhum número é escrito à mão: as tabelas e figuras vêm de `gerado/` e os
  valores citados no texto copiam-se de `gerado/pi5/hypotheses.md`,
  `calibration.md` e dos CSV.
- O veredicto das hipóteses é dos autores; `hypotheses.md` só dá a evidência.
- A Parte 1 não se altera: o que foi feito de forma diferente do plano está
  declarado em `03-metodo.tex` (Desvios ao plano).
