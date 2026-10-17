# Compila o relatório: pdflatex -> bibtex -> pdflatex x2.
#   make          gera main.pdf
#   make limpar   remove ficheiros auxiliares
NOME = main

$(NOME).pdf: $(NOME).tex preambulo.tex dados-revisao.tex referencias.bib seccoes/*.tex
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)
	bibtex $(NOME)
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)
	pdflatex -interaction=nonstopmode -halt-on-error $(NOME)

limpar:
	rm -f $(NOME).{aux,bbl,blg,log,out,toc,lof,lot} seccoes/*.aux

.PHONY: limpar
