# Relatório teórico — Projeto, Parte 1 (SRSI)

Revisão sistemática da literatura sobre segurança em comunicações MQTT e proposta
de arquitetura em camadas. LaTeX, estilo de referências IEEE.

## Compilar

```bash
make                    # pdflatex -> bibtex -> pdflatex x2  =>  main.pdf
make limpar             # remove ficheiros auxiliares
```

Requer uma distribuição TeX com `babel-portuges` (o estilo `IEEEtran-pt.bst`, cópia do IEEEtran com os termos em português, está na pasta) (TeX Live
completo; no Ubuntu: `texlive-lang-portuguese texlive-publishers`). No Overleaf,
carregar a pasta `report/` inteira e usar o compilador pdfLaTeX.

## Estrutura

| Ficheiro | Conteúdo |
|---|---|
| `main.tex` | capa e ordem das secções |
| `preambulo.tex` | pacotes, cores, macros (`\Sim`, `\Parc`, `\Nr`, `\Nao`) |
| `dados-revisao.tex` | números do processo de revisão (pesquisas, triagem, PRISMA, revisões) |
| `referencias.bib` | referências (autores, local, ano, páginas, DOI) |
| `seccoes/` | resumo, secções 1–9 (a 7 é o plano da segunda parte), anexos A (*strings*) e B (extração e referências dos estudos) |
| `figuras/` | `iscte-logo.png` (logótipo horizontal do sítio do Iscte) |
| `out/main.pdf` | cópia do PDF compilado |

## Dados da revisão (`rsl/`)

| Ficheiro | Conteúdo |
|---|---|
| `processar.py` | junta as exportações das bases, remove tipos não admitidos e duplicados, escreve `pesquisas/contagens.txt` e os CSV de `dados/` |
| `pesquisas/contagens.txt` | registos devolvidos por base e consulta |
| `dados/decisoes-triagem.csv` | decisão (I/E/D) e critério de cada um dos 2450 registos do `processar.py` (um só revisor); D marca 5 duplicados por título identificados depois da triagem |
| `dados/revisoes-decisoes.csv` | decisão e critério (RV1, RV2) de cada uma das 121 revisões candidatas |

As exportações das bases e os PDFs dos estudos (`pesquisas/*/`, `textos/`) e os CSV
com resumos não são publicados, por direitos de autor.

Para reproduzir as contagens, colocar as exportações em `rsl/pesquisas/<base>/` e
correr `python3 rsl/processar.py`.

## Âmbito

O relatório é teórico: descreve a arquitetura e o plano de avaliação da segunda
parte, sem resultados medidos. O código do repositório é o protótipo da segunda
parte.
