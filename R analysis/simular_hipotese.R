# Instalar o pacman, se ainda não estiver instalado
if (!require("pacman")) install.packages("pacman")

# Carregar os pacotes com pacman
pacman::p_load(ggstatsplot, ggplot2)

# Dados

set.seed(123)

x <- rnorm(100)
y <- 0.11 * x + rnorm(100, mean = 0, sd = 0.2)

y <- -1 * y

data <- data.frame(x,  y)

data %>%
  ggplot(aes(x, y)) + geom_point(size = 5,col = "black",fill = "red",shape=21) +
  theme_bw() + geom_smooth(method = "lm",alpha = .2) +
  labs(x = "X",
       y = "Y",
       title = "Representação gráfica da hipótese de trabalho") +
  theme(text = element_text(size = 35)) 

# Para representar a diferença entre grupos 
# criação dos grupos
g1 <- rnorm(100, mean = .9, sd = 1)
g2 <- rnorm(100, mean = 25, sd = 3)
g3 <- rnorm(100, mean = 20, sd = 3)
g4 <- rnorm(100, mean = .2, sd = .7)

# criação da base de dados
df <- data.frame(y = c(g1, g2, g3, g4), 
                 grupo = rep(c("Brancos", 
                               "Negros",
                               "Pardos",
                               "Amarelos/índigenas"), each = 100))

ggbetweenstats(df, grupo, y,
               centrality.label.args = list(size  = 5)) +
  labs(title = "Representação gráfica da hipótese de trabalho", 
       subtitle = "Dados Simulados",
       x = "",
       y = "Taxa de letalidade policial") +
  theme(text = element_text(size = 25))



# Simulação com apenas 2 grupos - Média de votos
g1 <- rnorm(100, mean = 25, sd = 1)   # Fraude
g2 <- rnorm(100, mean = 15, sd = 3)   # Não-Fraude

# Criação da base de dados
df <- data.frame(
  y = c(g1, g2),
  grupo = rep(c("Fraude", "Não-Fraude"), each = 100)
)

# Gráfico com ggbetweenstats
ggbetweenstats(df, grupo, y,
               centrality.label.args = list(size = 5)) +
  labs(
    title = "Representação gráfica da hipótese de trabalho", 
    subtitle = "Dados Simulados",
    x = "",
    y = "Média de votos"
  ) +
  theme(text = element_text(size = 25))

# Simulação com apenas 2 grupos - Retorno por cada R$1
# Já assumindo um modelo log-log
g1 <- rnorm(100, mean = .9, sd = 3)   # Fraude
g2 <- rnorm(100, mean = .3, sd = 1.5)   # Não-Fraude

# Criação da base de dados
df <- data.frame(
  y = c(g1, g2),
  grupo = rep(c("Fraude", "Não-Fraude"), each = 100)
)

# Gráfico com ggbetweenstats

ggbetweenstats(df, grupo, y,
               centrality.label.args = list(size = 5)) +
  labs(
    title = "Representação gráfica da hipótese de trabalho", 
    subtitle = "Dados Simulados",
    x = "",
    y = "Retorno médio por R$1"
  ) +
  theme(text = element_text(size = 25))



