# Material exclusivo da coleção para Bebês!
# https://livro-parabebes.hotmart.host/link-na-bio-0a68a338-9b84-4663-8045-cbd47d92f371
# Dalson Figueiredo, Recife, PE, 2025.

# 🎓 Tutorial do countfitteR: Análise de Distribuições para Dados de Contagem

#🔧 1. Instalar e carregar o pacote

install.packages("countfitteR")
library(countfitteR)

# Tudo no R depende dos pacotes que vc vai carregar.
# Cada pacote executa um conjunto específico de funções
# Se liga na documentação desse pacote:
# https://cran.r-project.org/web/packages/countfitteR/countfitteR.pdf
# Podemos seguir?

# 📦 2. Carregar a base de dados case_study

data("case_study") # carrega a base do pacote
head(case_study) # carrega a base na sua área de trabalho como planilha
View(case_study) # abre a base
# Observe que cada coluna representa um conjunto de dados de contagem

# 🔎 3. Verificar se os dados são válidos

validate_counts(case_study)

# Função: validate_counts()
# O que faz: Garante que os dados sejam numéricos e não negativos.
# Saída esperada: TRUE se os dados estiverem prontos para análise.
# E aí, deu certo aí? Sigamos.

# 🔄 4. Transformar para lista de contagens

contagens <- process_counts(case_study)
str(contagens)

# O que faz: Converte um data.frame em uma lista, onde cada item é uma variável de contagem (necessário para ajuste de modelos).
# Interpretação: Verifique que cada variável virou um vetor separado.

# ⚙️ 5. Ajustar modelos de distribuição
ajustes <- fit_counts(contagens, model = "all")

# Função: fit_counts()
# O que faz: Ajusta modelos de distribuição aos dados: Poisson, Binomial Negativa, ZIP, ZINB.
#Parâmetro model = "all" força o ajuste de todos os modelos disponíveis.
# Saída: Lista de modelos ajustados.

ajustes$L3_AF_DMSO_B_10_FITC_pois

# Veja que o objeto indica o valor do coeficiente +
# intervalo de confiança +
# BIC +
# o nome do modelo, no caso, pois de Poisson.

# 📈 6. Comparar distribuições teóricas com os dados reais

comparacao <- compare_fit(contagens, fitlist = ajustes)
head(comparacao)

# Função: compare_fit()
#O que faz: Calcula os valores teóricos esperados segundo os modelos e os compara com os dados empíricos.
# Interpretação: Verifique se o modelo captura bem os picos e zeros.
# Observe que, ao final, vc vai ter a indicação de que distribuição é aquela.

# 📊 7. Visualizar o ajuste

plot_fitcmp(comparacao)

# Função: plot_fitcmp()
# O que faz: Gera gráfico de barras dos valores esperados (modelo) e pontos vermelhos com os dados reais.
# Interpretação: Quanto mais os pontos vermelhos se aproximarem das barras, melhor o ajuste.

# 📋 8. Resumo dos ajustes

resumo <- summary_fitlist(ajustes)
print(resumo)

# Função: summary_fitlist()
# O que faz: Retorna uma tabela com os parâmetros estimados dos modelos, incluindo BIC, lambda, theta e probabilidade de zero inflado.
# Interpretação: Útil para comparar entre modelos.

# ✅ 9. Escolher o melhor modelo (com base no BIC)

melhor_modelo <- select_model(ajustes)
print(melhor_modelo)

# 10. Fazer isso de forma web

countfitteR::countfitteR_gui()

## E aí, viu como foi fácil?

## "Professor, tem como fazer novamente com outro exemplo?"
## Bora!!!

# Primeiro passo é simular a base de dados
# Vamos simular com 4 tipos de distribuicao

set.seed(123)

dados_simulados <- data.frame(
  poisson1 = rpois(100, lambda = 2),                      # 1. Distribuição de Poisson
  nb1      = rnbinom(100, size = 1.5, mu = 2),            # 2. Distribuição Binomial Negativa
  zip1     = rZIP(100, lambda = 2, r = 0.3),              # 3. Poisson Inflada de Zeros (ZIP)
  zinb1    = rZINB(100, size = 1.5, mu = 2, r = 0.3)       # 4. Binomial Negativa Inflada de Zeros (ZINB)
)


# Funções importantes
contagens_sim <- process_counts(dados_simulados)
ajustes_sim <- fit_counts(contagens_sim, model = "all")
comparacao_sim <- compare_fit(contagens_sim, ajustes_sim)
plot_fitcmp(comparacao_sim)
summary_fitlist(ajustes_sim)
select_model(ajustes_sim)

# "Professor, tem como incluir um texto explicando cada função?"
# Blz! Presta atenção, vamos fazer um por um. Qq dúvida, pare e leia novamente.
# Combinado?

# 1. Os dados simulados de contagem foram organizados em um data.frame, 
# contendo colunas com distribuições conhecidas (Poisson, Binomial Negativa, ZIP e ZINB). 

# 2. Aplicamos uma sequência de funções do pacote countfitteR para ajustar modelos probabilísticos 
# e avaliar o melhor ajuste para os dados:
  
process_counts(dados_simulados)
  
# Essa função transforma o data.frame de dados brutos em uma lista 
# onde cada elemento representa uma variável de contagem. 
# Essa estrutura é necessária para o ajuste posterior dos modelos estatísticos. 
# Também garante que valores ausentes ou inválidos sejam removidos, 
# mantendo somente contagens inteiras e não negativas.

fit_counts(contagens_sim, model = "all")

# Essa função ajusta uma série de modelos de distribuição de contagem para cada variável. 
# Ao usar model = "all", ela aplica todos os modelos disponíveis: Poisson, Binomial Negativa (NB),
# Poisson Inflacionado de Zeros (ZIP) e Binomial Negativa Inflacionada de Zeros (ZINB). 
# O resultado é uma lista de modelos ajustados com estimativas dos parâmetros.

compare_fit(contagens_sim, ajustes_sim)

# Após os modelos serem ajustados, essa função compara a distribuição empírica dos dados 
# com a distribuição teórica de cada modelo. Ela calcula a frequência esperada para cada contagem observada 
# com base nas distribuições ajustadas e estrutura os resultados em um data.frame 
# que pode ser visualizado ou plotado.

plot_fitcmp(comparacao_sim)

# Essa função gera um gráfico que sobrepõe os dados reais e os valores teóricos esperados para cada modelo. 
# As barras mostram os valores previstos pelo modelo e os pontos vermelhos representam os dados reais. 
# É uma ferramenta visual para avaliar a qualidade do ajuste: quanto mais próximos os pontos estiverem das barras, 
# melhor o modelo representa os dados.

summary_fitlist(ajustes_sim)

# Aqui é gerado um resumo numérico dos parâmetros estimados para cada modelo: média (lambda), dispersão (theta), 
# probabilidade de zero inflacionado (r) e o valor do BIC (Critério de Informação Bayesiano). 
# Esses resumos permitem comparar a qualidade do ajuste entre os diferentes modelos.

select_model(ajustes_sim)

# Por fim, essa função seleciona automaticamente o melhor modelo para cada variável, 
# com base no menor valor de BIC. O BIC penaliza modelos mais complexos, 
# favorecendo aqueles que explicam bem os dados com menos parâmetros. 
# O resultado é uma tabela indicando qual modelo foi considerado mais apropriado para cada variável.

# 🧠 Resumo do que foi aprendido
# Neste tutorial, você aprendeu a:
  
# Carregar e validar dados de contagem com o pacote countfitteR.

# Ajustar automaticamente diferentes modelos probabilísticos (Poisson, NB, ZIP, ZINB).

# Visualizar e comparar os dados empíricos com os valores esperados dos modelos.

# Selecionar o melhor modelo com base em critérios de informação (BIC).

# Reproduzir todo o fluxo com dados reais (case_study) e dados simulados.

# "Professor, senti falta de alguma referência teórica sobre o tema. Tem ai?"
# Se liga aqui:


# https://www.tandfonline.com/doi/abs/10.1080/00223890802634175
# https://cran.r-project.org/web/packages/pscl/vignettes/countreg.pdf
# https://stats.oarc.ucla.edu/stata/seminars/regression-models-with-count-data/

# Pronto, agora você tem o básico para aprender mais sobre o tema.
# Para outros materiais úteis, ver:
# https://livro-parabebes.hotmart.host/link-na-bio-0a68a338-9b84-4663-8045-cbd47d92f371

