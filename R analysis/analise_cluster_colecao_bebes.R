# Esse script vai te ajudar a entender o básico sobre análise de cluster!
# Antes de prosseguir, veja esses dois materiais:
# https://www.scielo.br/j/op/a/svvPhnRsrYwtqrjSPj98RPv/
# https://file.scirp.org/Html/22-7402230_48891.htm

# No R, tudo começa com a instalação de pacotes específicos para realizar 
# alguma função específica. Vamos instalar e carregar os seguintes pacotes:

# Instalar pacotes se necessário
if (!require("pacman")) install.packages("pacman")

# Carregar todos os pacotes necessários
pacman::p_load(
  tidyclust,       # para clustering com sintaxe tidy
  NbClust,         # para descobrir o número ótimo de clusters
  clusterWebApp,   # interface web para clustering
  cluster,         # métodos clássicos de clustering
  factoextra,      # visualização
  tidyverse        # manipulação e gráficos
)

# Vamos iniciar com dados simulados
# Se liga aqui nesse código:

# Simulando dois grupos bem distintos
set.seed(123)

df1 <- tibble(
  x = c(rnorm(50, 0, 1), rnorm(50, 5, 1)),
  y = c(rnorm(50, 0, 1), rnorm(50, 5, 1)),
  grupo = rep(c("Grupo 1", "Grupo 2"), each = 50) # variável de grupo
)

# Visualizar os dados
ggplot(df1, aes(x, y)) +
  geom_point() +
  labs(title = "Exemplo 1: Dois clusters bem separados")

# Então veja que os grupos estão bem separados, bem definidos!

ggplot(df1, aes(x, y)) +
  geom_point() +
  labs(title = "Exemplo 1: Dois clusters bem separados") +
  geom_smooth(method = "lm") # adiciona reta de regressão

# Então veja que interessante: se a gente rodar uma regressão com todos os casos
# Vamos ter um coeficiente positivo. Mas veja que isso não é uma boa representação
# da relação entre x e y

# Ajustar uma regressão separada para cada grupo visualmente
ggplot(df1, aes(x, y, color = grupo)) +
  geom_point() +
  geom_smooth(method = "lm", se = FALSE) +
  labs(title = "Regr. linear separada por grupo") 

# Viu aí? Muito diferente né? Temos aqui uma boa motivação para considerar
# a natureza dos grupos em nossas análises. 

## Usando o tidyclust

# Especificação do modelo
mod_kmeans <- k_means(num_clusters = 2) %>% 
  set_engine("stats")

#O que faz:
# estamos dizendo ao R que queremos usar o algoritmo K-means para agrupar os dados. 
# Estamos especificando que queremos 2 grupos (ou clusters) e que o método de cálculo 
# será feito com o motor (engine) stats, que é o pacote base do R. 
# Esse comando não executa o agrupamento ainda – apenas define o modelo.

# Ajuste com fórmula
fit_kmeans <- fit(mod_kmeans, ~., data = df1)

# Nesta linha, usamos a função fit() para ajustar (ou treinar) o modelo com base nos dados reais.
# O ~. significa que queremos usar todas as variáveis do df como entrada.
# data = df1 é o conjunto de dados.
# Ao final, o objeto fit_kmeans contém um modelo de K-means treinado com os dados simulados.

# Predição
df_pred <- augment(fit_kmeans, new_data = df1)

# O que essa função faz?
# Aqui usamos augment() para adicionar as previsões do modelo ao nosso conjunto de dados.
# Mais especificamente, ela devolve os dados originais com uma nova coluna chamada .pred_cluster, 
# indicando a qual cluster cada observação foi atribuída pelo modelo.

# Visualização
ggplot(df_pred, aes(x, y, color = .pred_cluster)) +
  geom_point(size = 3) +
  labs(title = "Clusters com tidyclust + kmeans")

# O que está sendo exibido?
# Esse gráfico mostra os pontos dos dados (base df) no plano cartesiano, com as coordenadas x e y.
# Cada ponto é colorido de acordo com o cluster atribuído pelo modelo (.pred_cluster).
# O título do gráfico indica que os grupos foram gerados usando o algoritmo K-means com o pacote tidyclust.

# "Professor, mas o resultado final é exatamente igual ao resultado inicial. Fiquei sem entender".
# Vc está certíssimo, isso mostra que vc entendeu a parada.
# Veja, como estamos com dados simulados, a solução fica bem certinha. É diferente quando estamos com
# dados reais. Outra coisa, na análise de cluster, o algoritmo SEMPRE acha uma solução. Então, temos q
# avaliar criticamente em que medida os grupos encontrados fazem sentido teórico. 
# Vamos continuar explorando outros conceitos importantes e depois faremos outros exercícios para
# consolidar o conteúdo, blz?

# Visualização dos Centróides dos Clusters

# Extração dos centróides
extract_centroids(fit_kmeans)

centroides <- extract_centroids(fit_kmeans)

# O que essa função faz?
# Ela retorna um tibble com a posição média de cada cluster nos eixos x e y. 
# Esses pontos representam o "coração" de cada grupo — onde se concentram os dados daquele cluster.
# Imagine o centroide como um local que minimiza a distancia entre ele e todos os outros pontos

# Passo 2: plotar os dados com cores por cluster
ggplot(df_pred, aes(x, y, color = .pred_cluster)) +
  geom_point(size = 3, alpha = .5) +
  geom_point(data = centroides, 
             aes(x, y, color = .cluster),  # agora sim, a variável existe
             shape = 4, size = 12, stroke = 3) +
  labs(title = "Clusters com centróides coloridos por grupo") +
  theme_minimal()

# Outro elemento importante é avaliar a qualidade do ajuste
# Avaliação da Qualidade dos Clusters (Métricas)
# Vejamos algumas medidas usualmente empregadas

# Matriz de distâncias

df1 <-  df1 %>%
  select(-grupo) # Remover a variável de grupo

dists <- dist(df1) 

# Silhueta média
silhouette_avg(fit_kmeans, dists = dists)

# A silhueta mede o quão bem uma observação está posicionada dentro do seu cluster em relação aos outros. 
# Varia de -1 (ruim) a 1 (ótimo).

# ps: Um valor acima de 0.5 já indica uma separação razoável entre os grupos.
# Nosso valor foi de 0,775, ou seja, muito acima do ponto de corte.

# SSE Ratio (sse_ratio())
sse_ratio(fit_kmeans)

# Compara o erro de agrupamento dentro dos clusters (WSS) com o total (TSS). 
# Quanto mais próximo de 1, melhor a compactação dos clusters.

#  Testar Vários Números de Clusters

# Suponha agora que vc saiu de casa na sexta-feira e só voltou domingo a noite!
# Farra pesada. E aí vc acabou esquecendo do numero de grupos da base de dados
# Será que tem como determinar isso de forma automática e confiável?

res_nbclust <- NbClust(
  data = df1,
  distance = "euclidean",
  min.nc = 2,
  max.nc = 6,
  method = "kmeans",
  index = "all"  # calcula todos os 30 índices
)

# Número de clusters sugerido pela maioria dos índices
res_nbclust$Best.nc

# Tabela com contagem de votos por número de clusters
table(res_nbclust$Best.nc[1, ])


# O valor com maior frequência de votos é o número de clusters recomendado.

# Observe que 14 soluções apontam para 2 clusters

# Professor, tem alguma forma de visualizar?
# Tem!

barplot(
  table(res_nbclust$Best.nc[1, ]),
  xlab = "Número de Clusters",
  ylab = "Número de Critérios que Recomendaram",
  col = "steelblue",
  main = "Resultado dos Critérios Internos (NbClust)"
)

# "Professor, percebi que foram utilizados diferentes pacotes para 
# tarefas específicas. Como eu acho esses pacotes?"
# Fiz um script que pega todos os pacotes de R que citam "cluster" na descrição
# https://docs.google.com/spreadsheets/d/16sJSiRVsSc0s2ZuCXLE1qny7zs4_ZtsK26Yjfq0mL8g/edit?gid=189924490#gid=189924490
# Entra ai e estude!

# O último pacote que iremos explorar é o clusterWebApp
# Ele é super novo, foi lançado agora em julho de 2025

# Carregar o pacote
library(clusterWebApp)

# Veja que legal!

run_app()

# O aplicativo é bem intuitivo. Vc pode fazer o upload dos dados
# e já começar a analisar
# Se liga na documentação:
# https://cran.r-project.org/web/packages/clusterWebApp/clusterWebApp.pdf

# De toda forma, vou mostrar aqui algumas das funções!

data <- prepare_data("iris")  # Também pode usar: "USArrests", "mtcars", "CO2", "swiss", "Moons"
head(data)

# Essa função vai excluir variáveis inadequadas da análise

data <- scale(iris[, 1:4]) # Vai padronizar as variaveis

# Aplicando KMeans com k = 3
result <- run_clustering(data, method = "KMeans", k = 3)

# Visualizando os rótulos atribuídos
print(result$cluster)

sil <- silhouette(result$cluster, dist(data))

compute_silhouette(sil)

plot_elbow(data)

plot_silhouette(sil)

plot_radar(data, clusters = 3)

# E aí, viu como é fácil?

# Se liga nesses extras!

# Instalar se necessário
install.packages(c("ggplot2", "factoextra", "cluster"))

# Carregar os pacotes
library(ggplot2)
library(factoextra)
library(cluster)

set.seed(123)

meus_dados <- rbind(
  data.frame(x = rnorm(25, -2), y = rnorm(25, 0)),
  data.frame(x = rnorm(25, 2), y = rnorm(25, 0))
)

fviz_nbclust(meus_dados, kmeans, method = "wss") +
  labs(title = "Elbow Method", x = "Number of Clusters", y = "Total Within-Cluster SS") +
  theme_minimal()

k2 <- kmeans(meus_dados, centers = 2, nstart = 25)

# Simula dados (ou substitua por sua base real)
set.seed(123)

meus_dados <- rbind(
  data.frame(x = rnorm(25, -2), y = rnorm(25, 0)),
  data.frame(x = rnorm(25, 2), y = rnorm(25, 0))
)

# k-means
k2 <- kmeans(meus_dados, centers = 2, nstart = 25)

# Visualização dos clusters (apenas com as colunas numéricas)
fviz_cluster(k2, data = meus_dados, 
             geom = "point", ellipse.type = "euclid", 
             palette = c("#F8766D", "#00BFC4"),
             ggtheme = theme_minimal()) +
  labs(title = "Clustering Result - KMeans",
       x = "Variável x", y = "Variável y")


# ---------------------------------------
# RESUMO FINAL – ENTENDENDO CLUSTERIZAÇÃO NO R
# ---------------------------------------

# Ao longo deste script, você aprendeu o básico sobre análise de cluster, uma técnica usada
# para identificar grupos naturais em seus dados. Vimos como simular dados, aplicar o algoritmo
# K-means, visualizar os resultados, extrair centróides e avaliar a qualidade do agrupamento.

# PRINCIPAIS CONCEITOS:

# 1. Clustering não supervisionado:
#    A ideia é deixar o algoritmo encontrar grupos de dados semelhantes sem usar rótulos prévios.

# 2. K-means:
#    É um dos algoritmos mais populares. Ele tenta dividir os dados em K grupos (clusters), 
#    minimizando a distância entre os pontos de cada grupo e o seu centróide.

# 3. Visualização:
#    Usamos gráficos para mostrar como os grupos se formaram no espaço bidimensional 
#    e onde os centróides (centros dos grupos) estão localizados.

# 4. Avaliação dos clusters:
#    • Silhueta: mede o quão bem os pontos se encaixam no seu grupo.
#    • SSE Ratio: compara a variabilidade dentro e entre os grupos.
#    • Elbow Method: ajuda a escolher o número ideal de clusters visualmente.
#    • NbClust: calcula automaticamente dezenas de critérios para sugerir o número ótimo de grupos.

# 5. clusterWebApp:
#    Ferramenta interativa e recente que permite aplicar e visualizar algoritmos de cluster 
#    com poucos cliques. Excelente para explorar bases reais rapidamente.

# Agora é contigo: pratique com diferentes bases, explore outros algoritmos como DBSCAN ou 
# hierárquico, e tente combinar clustering com outras análises (como regressão por grupo).

# Bons estudos e boas análises! 🚀


