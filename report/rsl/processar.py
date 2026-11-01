#!/usr/bin/env python3
"""Junta as exportações das pesquisas, remove registos fora de âmbito e duplicados.

Uso: python3 processar.py   (a partir de report/rsl/)

Entradas: pesquisas/<base>/*.csv|*.bib
Saídas:   dados/registos.csv      todos os registos exportados, com o destino de cada um
          dados/triagem.csv       registos únicos a triar por título e resumo (string principal)
          dados/revisoes.csv      registos únicos da string secundária
          pesquisas/contagens.txt números para a Tabela 6 e o PRISMA
"""
import csv
import glob
import os
import re
import unicodedata
from collections import Counter, OrderedDict

csv.field_size_limit(10**8)
AQUI = os.path.dirname(os.path.abspath(__file__))
PESQ = os.path.join(AQUI, 'pesquisas')
DADOS = os.path.join(AQUI, 'dados')

# Tipos admitidos (CI2: revista, conferência ou workshop com revisão por pares).
TIPOS_IEEE = {'IEEE Conferences', 'IEEE Journals', 'IEEE Early Access Articles',
              'IET Conferences', 'IEICE Journals', 'River Publishers Journals',
              'Additional Conference Content Conferences'}
TIPOS_SCOPUS = {'Article', 'Conference paper'}
TIPOS_SCOPUS_REVISOES = TIPOS_SCOPUS | {'Review'}  # só na string secundária
TIPOS_SD = {'article'}


def norm_doi(d):
    d = (d or '').strip().lower()
    d = re.sub(r'^(https?://(dx\.)?doi\.org/|doi:)', '', d)
    return d


def norm_titulo(t):
    t = unicodedata.normalize('NFKD', t or '').encode('ascii', 'ignore').decode().lower()
    return re.sub(r'[^a-z0-9]+', ' ', t).strip()


def ler_csv(caminho):
    with open(caminho, newline='', encoding='utf-8-sig', errors='replace') as f:
        return list(csv.DictReader(f))


def ler_bib(caminho):
    texto = open(caminho, encoding='utf-8', errors='replace').read()
    registos = []
    for bloco in re.split(r'\n(?=@\w+\{)', texto):
        m = re.match(r'@(\w+)\{', bloco.strip())
        if not m:
            continue
        campos = {k.lower(): v for k, v in re.findall(r'^\s*(\w+)\s*=\s*\{(.*?)\},?\s*$', bloco, re.M | re.S)}
        campos['_tipo'] = m.group(1).lower()
        registos.append(campos)
    return registos


def registo(base, string, ficheiro, tipo, titulo, resumo, ano, fonte, doi):
    return OrderedDict(base=base, string=string, ficheiro=ficheiro, tipo=tipo,
                       titulo=' '.join((titulo or '').split()), resumo=' '.join((resumo or '').split()),
                       ano=ano, fonte=fonte, doi=norm_doi(doi))


def carregar():
    regs = []
    for f in sorted(glob.glob(os.path.join(PESQ, 'ieee', '*.csv'))):
        string = 'secundaria' if 'secundaria' in f else 'principal'
        for r in ler_csv(f):
            regs.append(registo('IEEE Xplore', string, os.path.basename(f), r.get('Document Identifier', ''),
                                r.get('Document Title'), r.get('Abstract'), r.get('Publication Year'),
                                r.get('Publication Title'), r.get('DOI')))
    for f in sorted(glob.glob(os.path.join(PESQ, 'scopus', '*.csv'))):
        string = 'secundaria' if 'secundaria' in f else 'principal'
        for r in ler_csv(f):
            regs.append(registo('Scopus', string, os.path.basename(f), r.get('Document Type', ''),
                                r.get('Title'), r.get('Abstract', ''), r.get('Year'),
                                r.get('Source title'), r.get('DOI')))
    for f in sorted(glob.glob(os.path.join(PESQ, 'sciencedirect', '*.bib'))):
        string = 'secundaria' if 'secundaria' in f else 'principal'
        for r in ler_bib(f):
            regs.append(registo('ScienceDirect', string, os.path.basename(f), r['_tipo'],
                                r.get('title'), r.get('abstract'), r.get('year'),
                                r.get('journal') or r.get('booktitle'), r.get('doi')))
    return regs


def tipo_admitido(r):
    if r['base'] == 'Scopus' and r['string'] == 'secundaria':
        return r['tipo'] in TIPOS_SCOPUS_REVISOES
    return r['tipo'] in {'IEEE Xplore': TIPOS_IEEE, 'Scopus': TIPOS_SCOPUS, 'ScienceDirect': TIPOS_SD}[r['base']]


def deduplicar(regs):
    """Agrupa por DOI e, sem DOI, por título normalizado. Guarda o registo com resumo."""
    grupos = OrderedDict()
    por_titulo = {}
    for r in regs:
        chave_t = norm_titulo(r['titulo'])
        chave = r['doi'] or por_titulo.get(chave_t) or 't:' + chave_t
        if chave in grupos:
            g = grupos[chave]
            g['bases'].add(r['base'])
            if not g['resumo'] and r['resumo']:
                g['resumo'] = r['resumo']
        else:
            grupos[chave] = dict(r, bases={r['base']})
        por_titulo.setdefault(chave_t, chave)
    return list(grupos.values())


def escrever(caminho, linhas, campos):
    with open(caminho, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=campos, extrasaction='ignore')
        w.writeheader()
        w.writerows(linhas)


def main():
    os.makedirs(DADOS, exist_ok=True)
    regs = carregar()
    for r in regs:
        r['destino'] = 'mantido' if tipo_admitido(r) else 'removido: tipo de documento'
    escrever(os.path.join(DADOS, 'registos.csv'), regs, list(regs[0].keys()))

    linhas = ['Registos devolvidos (= exportados), por base e string:']
    for (base, string), n in sorted(Counter((r['base'], r['string']) for r in regs).items()):
        linhas.append(f'  {base:14s} {string:10s} {n}')

    resultado = {}
    for string, saida in (('principal', 'triagem.csv'), ('secundaria', 'revisoes.csv')):
        sel = [r for r in regs if r['string'] == string]
        admit = [r for r in sel if r['destino'] == 'mantido']
        unicos = deduplicar(admit)
        unicos.sort(key=lambda r: (r['ano'] or '', norm_titulo(r['titulo'])))
        for i, r in enumerate(unicos, 1):
            r['id'] = f'{"R" if string == "principal" else "V"}{i:04d}'
            r['bases'] = '; '.join(sorted(r['bases']))
        escrever(os.path.join(DADOS, saida), unicos,
                 ['id', 'titulo', 'ano', 'fonte', 'doi', 'bases', 'resumo'])
        resultado[string] = (len(sel), len(sel) - len(admit), len(admit) - len(unicos), len(unicos),
                             sum(1 for r in unicos if not r['resumo']))
        n, tipo, dup, uni, sem_resumo = resultado[string]
        linhas += ['', f'String {string}:',
                   f'  identificados           {n}',
                   f'  removidos por tipo      {tipo}',
                   f'  duplicados removidos    {dup}',
                   f'  únicos para triagem     {uni}',
                   f'  sem resumo              {sem_resumo}']
    open(os.path.join(PESQ, 'contagens.txt'), 'w', encoding='utf-8').write('\n'.join(linhas) + '\n')
    print('\n'.join(linhas))


if __name__ == '__main__':
    main()
