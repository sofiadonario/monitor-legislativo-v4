# Esse script vai te ajudar a fazer gráficos de linha como um profissional

# O primeiro passo é instalar esses pacotes com a comando install.packages("nome do pacote")
# Se vc já tem instalado, basta chamar com o comando library ("nome do pacote)
# Vamos nessa então!

# Pacotes
library(readxl)
library(dplyr)
library(ggplot2)

# Dados

tven <- read.csv("https://docs.google.com/spreadsheets/d/e/2PACX-1vTxjv4IQ7QxVxA87CpLkYCzFScoVLDdQgYDbfrJSkqqvve1-19HxKjrFtyi21GGzYKxnwwEBiGTzHHY/pub?output=csv")

names(tven) # Para ver o nome das variaveis da base de dados
# Observe que temos 4 variaveis: tipo, data, turnout (taxa de comparecimento) e ano

tven$turnout <- as.numeric(tven$turnout) # transforma turnout em variavel numerica

tven <- na.omit(tven) # Excluir valores ausentes

mean(tven$turnout) # Calcula a média do turnout
sd(tven$turnout) # Calcula o desvio padrão do turnout
max(tven$turnout) # Calcula o turnout mais elevado (valor máximo)
min(tven$turnout) # Calcula o turnout mais baixo (valor mínimo)

tven <- tven %>%
  group_by(year) %>%
  summarise(avg_t = mean(turnout)) # Vamos criar uma base de dados agregada por ano
                                   # isso é importante para evitar problemas na visualização

tven$avg_t <- round(tven$avg_t, 1) # arredondar o valor para 1 casa decimal

tven$year <- as.character(tven$year) # trasnformar a variavel ano em caractere

tven %>%
  ggplot(aes(year, avg_t)) + 
  geom_point(size = 8, alpha = .35, col = "darkblue") +
  geom_line(group = 1, alpha = .15) +
  geom_text_repel(aes(label = avg_t), size = 8) +
  theme_bw() +
  ylim(0, 100) +
  geom_hline(yintercept = mean(tven$avg_t), linetype = "dashed",
             color = "red", size = 2, alpha = .4) +
  labs(x = "",
       y = "Turnout (%)",
       title = "Average turnout (%) per election cycle",
       subtitle = "Venezuela (1998 - 2023)",
       caption = "Source: https://www.electionguide.org/countries/id/231/") +
  theme(text = element_text(size = 25),
        axis.text.x = element_text(angle = 45, hjust = 1))   

# https://www.electionguide.org/countries/id/231/
# nesse site voce pode pegar a taxa de comparecimento de todos os países do mundo
# E aí, vamos praticar?

# Qualquer dúvida, entre em contato. Abs,
# @DalsonFigueired
