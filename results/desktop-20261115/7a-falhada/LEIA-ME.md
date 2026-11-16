# Primeira tentativa da etapa 7a (falhada)

Campanha `desktop-20261115`, iniciada 2026-11-15 22:59 UTC no commit `2f5f62c`.
Na execução 70/120 (K1, repetição 6) o gateway não respondeu ao pedido `summary`
em 30 s e o controlador terminou (`queue.Empty`, ver `../campaign-desktop-20261115.log`).
A saída de erro do gateway não foi guardada; a origem não foi determinada.
As 69 execuções anteriores (`runs.csv`) são normais e ficam como registo; não
entram na análise.

As etapas 7b, 6 e 7c dessa campanha correram sem erro e são as usadas.
A etapa 7a foi repetida sozinha em 2026-11-16 (mesmo commit, árvore limpa, mesmos
argumentos, mesma afetação de núcleos), com saída em `results/desktop-20261116-custo`,
depois movida para esta campanha (`../runs.csv`, `../saturation.csv`, `../manifest.json`;
registo em `../campaign-desktop-20261116-custo.log`).
