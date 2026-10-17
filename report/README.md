# Relatório teórico — Projeto, Parte 1 (SRSI)

Revisão sistemática da literatura sobre segurança em comunicações MQTT e proposta
de arquitetura em camadas. LaTeX, estilo de referências IEEE.

## Compilar

```bash
make                    # pdflatex -> bibtex -> pdflatex x2  =>  main.pdf
make limpar             # remove ficheiros auxiliares
```

Requer uma distribuição TeX com `babel-portuges` e `IEEEtran.bst` (TeX Live
completo; no Ubuntu: `texlive-lang-portuguese texlive-publishers`). No Overleaf,
carregar a pasta `report/` inteira e usar o compilador pdfLaTeX.

## Estrutura

| Ficheiro | Conteúdo |
|---|---|
| `main.tex` | capa (campos a preencher no topo), ordem das secções |
| `preambulo.tex` | pacotes, cores, macros (`\Sim`, `\Parc`, `\Nr`, `\Nao`) |
| `dados-revisao.tex` | **números do processo de revisão, a preencher** |
| `referencias.bib` | 51 referências verificadas (autores, local, ano, páginas, DOI) |
| `seccoes/` | resumo, glossário, secções 1–8, anexos A (strings) e B (extração) |
| `figuras/` | opcional: `iscte-logo.png` substitui o marcador da capa |

## Antes de entregar

1. **Capa** (`main.tex`): nome do mestrado, autores e números, docente.
2. **Executar as pesquisas** do Anexo A nas cinco bases de dados e a triagem no
   Parsifal; preencher em `dados-revisao.tex` as contagens por base, duplicados,
   triagem, texto integral, kappa e data. Tudo o que falta aparece a vermelho no PDF.
3. **Confirmar a extração na leitura integral**: a classificação das propriedades
   (Tabelas 12 e 16, Anexo B) foi feita a partir dos resumos dos estudos. As células
   "não reportado" (–) têm de ser confirmadas na terceira passagem de leitura;
   se um estudo tratar, por exemplo, anti-repetição, corrigir a célula e os
   números da Figura 6 e das Secções 5.3 e 7.1.
4. Se a triagem for feita por um só revisor, adaptar o texto do kappa (Secção 3.7).
