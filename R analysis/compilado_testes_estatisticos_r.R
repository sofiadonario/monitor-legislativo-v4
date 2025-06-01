# Tutorial: Usando o pacote automatedtests para escolher testes estatísticos automaticamente
# O pacote automatedtests facilita a vida ao escolher e executar o teste estatístico mais apropriado 
# para os seus dados. Ele devolve um objeto com os resultados organizados, permitindo saber:
  
# Qual teste foi aplicado

# Qual foi o valor-p

# Se foi significativo ou não

# Qual o tamanho do efeito

# Se os dados são paramétricos

####################################################

# Instale o pacote a partir do CRAN (quando estiver disponível)
install.packages("automatedtests")

# Carregue o pacote
library(automatedtests)

# Exemplo 1: Teste entre espécies e comprimento da sépala (base iris)

# Usa a função principal do pacote
teste1 <- automatical_test(iris$Species, iris$Sepal.Length)

# Resultado detalhado
teste1$get_result()

# Exemplo 2: Correlação entre comprimento e largura da sépala
teste2 <- automatical_test(iris$Sepal.Length, iris$Sepal.Width)

# Tipo de teste aplicado
teste2$get_test()

# Resultado detalhado
teste2$get_result()

#  Exemplo 3: Teste de proporção (usar tabela de fumantes vs não fumantes)

# Tabela fictícia de fumantes
smoking_status <- ifelse(mtcars$gear == 4, "smoker", "non-smoker")

# Executa o teste comparando com proporção esperada 0.5 (por exemplo)
teste3 <- automatical_test(smoking_status, compare_to = 0.5)

teste3$get_result()

# Exemplo 4: Teste pareado (antes e depois, usando dados de pressão arterial)

before <- c(120, 122, 119, 130, 125)
after  <- c(118, 121, 117, 127, 124)
teste4 <- automatical_test(before, after, paired = TRUE)

teste4$get_result()

# Exemplo 5: ANOVA com base PlantGrowth

teste5 <- automatical_test(PlantGrowth$group, PlantGrowth$weight)

teste5$get_result()

# Exemplo 6: Diferença entre dois grupos independentes

set.seed(123)
grupo <- rep(c("A", "B"), each = 30)
valores <- c(rnorm(30, 10, 2), rnorm(30, 12, 2))

teste6 <- automatical_test(grupo, valores)
teste6$get_result()

# Exemplo 7: Correlação de Pearson simulada

set.seed(42)
x <- rnorm(50)
y <- 2*x + rnorm(50)

teste7 <- automatical_test(x, y)
teste7$get_result()

# Exemplo 8: Proporção simulada (1 grupo binário)

set.seed(101)
grupo_bin <- sample(c("sucesso", "fracasso"), size = 100, replace = TRUE, prob = c(0.7, 0.3))

# Assume proporção nula de 0.5 para comparação
teste8 <- automatical_test(grupo_bin, compare_to = 0.5)

teste8$get_result()

#  Exemplo 9: Dados pareados simulados

set.seed(77)
antes <- rnorm(20, mean = 50, sd = 5)
depois <- antes + rnorm(20, mean = -2, sd = 3)

teste9 <- automatical_test(antes, depois, paired = TRUE)
teste9$get_result()

# Exemplo 10: Comparando três grupos simulados (ANOVA ou Kruskal)

set.seed(888)
grupo <- rep(c("grupo1", "grupo2", "grupo3"), each = 20)
valores <- c(rnorm(20, 10), rnorm(20, 12), rnorm(20, 15))

teste10 <- automatical_test(grupo, valores)
teste10$get_result()

## DICAS ADICIONAIS
# Para verificar se o teste foi significativo:
  
teste10$is_significant()

# Para saber qual teste foi escolhido automaticamente:
  
teste10$get_test()

# Para descobrir a "força" do resultado (ex: diferença de médias, r de correlação, etc):
  
teste10$get_strength()

# Para saber se o teste é paramétrico:
  
teste10$is_parametric()

# Para saber mais, ver: https://cran.r-project.org/web/packages/automatedtests/automatedtests.pdf 
# https://cran.r-project.org/web/packages/automatedtests/vignettes/automatical_test_vignette.html

#  Professor, comecei a entender. Tem como incluir mais exemplos?
# Só se for agora.
# Se segura aí que iremos fazer 23 exemplos.
# Tá preparado?


## 1. One-proportion test
# Testa se a proporção observada difere de uma proporção hipotética

# Suponha que 60 de 100 pessoas responderam "sim"
sucessos <- 60
n <- 100
prop_esperada <- 0.5  # H0: proporção = 50%

# Executa o teste
resultado <- prop.test(sucessos, n, p = prop_esperada)

# Exibe o resultado
print(resultado)

## 2. Chi-square goodness-of-fit test
# Testa se uma distribuição observada difere de uma esperada
observado <- c(30, 50, 20)
esperado <- c(0.3, 0.4, 0.3)
chisq.test(x = observado, p = esperado)


## 3. One-sample Student’s t-test
# Testa se a média de uma amostra difere de um valor
x <- rnorm(30, mean = 5)
t.test(x, mu = 5)


## 4. One-sample Wilcoxon test
# Versão não paramétrica do t-teste para uma amostra
x <- rnorm(30, mean = 5)
wilcox.test(x, mu = 5)


## 5. Multiple linear regression
# Regressão com múltiplas variáveis explicativas
df <- data.frame(y = rnorm(100), x1 = rnorm(100), x2 = rnorm(100))
summary(lm(y ~ x1 + x2, data = df))


## 6. Binary logistic regression
# Regressão logística para desfecho binário
df <- data.frame(y = rbinom(100, 1, 0.5), x = rnorm(100))
summary(glm(y ~ x, data = df, family = binomial))


## 7. Multinomial logistic regression
# Regressão logística com mais de duas categorias
library(nnet)
df <- data.frame(y = factor(sample(1:3, 100, replace = TRUE)), x = rnorm(100))
summary(multinom(y ~ x, data = df))


## 8. Pearson correlation
# Correlação linear entre duas variáveis
x <- rnorm(100)
y <- x + rnorm(100)
cor.test(x, y, method = 'pearson')


## 9. Spearman’s rank correlation
# Correlação baseada em postos
x <- rnorm(100)
y <- x + rnorm(100)
cor.test(x, y, method = 'spearman')


## 11. McNemar’s test
# Teste para variáveis dicotômicas emparelhadas
matriz <- matrix(c(30, 10, 15, 45), nrow = 2)
mcnemar.test(matriz)


## 12. Fisher’s exact test
# Teste exato para associação em tabelas pequenas
matriz <- matrix(c(1, 9, 11, 3), nrow = 2)
fisher.test(matriz)


## 13. Chi-square test of independence
# Teste para independência entre duas variáveis categóricas
matriz <- matrix(c(10, 20, 20, 40), nrow = 2)
chisq.test(matriz)


## 14. Student’s t-test for independent samples
# Compara médias de dois grupos independentes
x1 <- rnorm(30, mean = 5)
x2 <- rnorm(30, mean = 6)
t.test(x1, x2, var.equal = TRUE)


## 15. Welch’s t-test for independent samples
# Igual ao anterior, mas sem assumir variâncias iguais
x1 <- rnorm(30, mean = 5, sd = 1)
x2 <- rnorm(30, mean = 6, sd = 2)
t.test(x1, x2)


## 16. Mann-Whitney U test
# Teste não paramétrico para duas amostras independentes
x1 <- rnorm(20)
x2 <- rnorm(20, mean = 1)
wilcox.test(x1, x2)


## 17. Student’s t-test for paired samples
# Compara médias de duas amostras emparelhadas
before <- rnorm(30, mean = 5)
after <- before + rnorm(30)
t.test(before, after, paired = TRUE)


## 18. Wilcoxon signed-rank test
# Teste não paramétrico para dados emparelhados
wilcox.test(before, after, paired = TRUE)


## 19. One-way ANOVA
# Compara médias de três ou mais grupos
grupo <- factor(rep(1:3, each = 20))
y <- c(rnorm(20, mean = 5), rnorm(20, mean = 6), rnorm(20, mean = 7))
summary(aov(y ~ grupo))


## 20. Welch’s ANOVA
# Versão do ANOVA que não assume variâncias iguais
oneway.test(y ~ grupo)


## 22. Kruskal-Wallis test
# Teste não paramétrico para mais de dois grupos independentes
kruskal.test(y ~ grupo)


## 23. Friedman test
# Teste não paramétrico para medidas repetidas
library(stats)
df <- matrix(rnorm(30), ncol = 3)
friedman.test(df)




