# Relatório da Parte 2: pdflatex -> bibtex -> pdflatex x2.
#   make                              gera main.pdf
#   make dados PI=pi5-20261201 [DESKTOP=desktop-20261202]
#                                     copia as tabelas e figuras geradas por
#                                     tools/analysis/analyze.py para gerado/
#   make limpar                       remove ficheiros auxiliares
SHELL := /bin/bash
NOME = main
ANALISE = ../../build/analysis

$(NOME).pdf: $(NOME).tex ../preambulo.tex ../referencias.bib seccoes/*.tex $(wildcard gerado/*/*)
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)
	-bibtex $(NOME)
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)

dados:
	@test -n "$(PI)" || { echo "uso: make dados PI=<campanha> [DESKTOP=<campanha>]"; exit 1; }
	mkdir -p gerado/pi5
	cp $(ANALISE)/$(PI)/*.tex $(ANALISE)/$(PI)/*.md $(ANALISE)/$(PI)/*.csv gerado/pi5/
	@if [ -n "$(DESKTOP)" ]; then mkdir -p gerado/desktop && \
	  cp $(ANALISE)/$(DESKTOP)/*.tex $(ANALISE)/$(DESKTOP)/*.md $(ANALISE)/$(DESKTOP)/*.csv gerado/desktop/; fi

limpar:
	rm -f $(NOME).{aux,bbl,blg,log,out,toc,lof,lot} seccoes/*.aux

.PHONY: dados limpar
