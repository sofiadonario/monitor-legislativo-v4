## Esse script vai te ajudar a melhorar a qualidade dos seus gráficos de dispersão

# Raiz da replicabidade
set.seed(666)

# Simulação
n <- 100
x <-rnorm(n, 15, 5)
erro <- rnorm(n, 0, 1)
y <- .31 * x + erro

df <- data.frame(x, y)

# Nível 1

plot(df) # gráfico com o comando básico do R

# Nível 2

library(ggplot2)
library(dplyr)

g2<-df %>%
  ggplot(aes(x, y)) + geom_point() # agora com o básico do ggplot2
g2

# Nível 3

g3<-df %>%
  ggplot(aes(x, y)) + geom_point() +
  theme_bw() +
  labs(x = "Nome da variável X",
       y = "Nome da variável Y",
       title = "Título do gráfico",
       subtitle = "Algum subtitulo com uma info bacana",
       caption = "Fonte: fonte dos dados/de quem fez") # vamos incluir nomes nos eixos
                                                       # titulo, subtitulo e fonte
g3


# Nível 4

g4<-df %>%
  ggplot(aes(x, y)) + geom_point() +
  theme_bw() +
  labs(x = "Nome da variável X",
       y = "Nome da variável Y",
       title = "Título do gráfico",
       subtitle = "Algum subtitulo com uma info bacana",
       caption = "Fonte: fonte dos dados/de quem fez") +
  geom_smooth(method = "lm") # vamos adicionar a linha de regressão
g4

# Nível 5

library(ggpubr)

g5<-df %>%
  ggplot(aes(x, y)) + geom_point() +
  theme_bw() +
  labs(x = "Nome da variável X",
       y = "Nome da variável Y",
       title = "Título do gráfico",
       subtitle = "Algum subtitulo com uma info bacana",
       caption = "Fonte: fonte dos dados/de quem fez") +
  geom_smooth(method = "lm")  +
  stat_cor(method = "pearson", label.x = 3, 
           label.y = 10) # vamos adicionar o coeficiente de correlação
g5

# Nível 6

library(ggpubr)

g6<-df %>%
  ggplot(aes(x, y)) + geom_point(col = "darkgreen", size = 5, alpha = .2) +
  theme_bw() +
  labs(x = "Nome da variável X",
       y = "Nome da variável Y",
       title = "Título do gráfico",
       subtitle = "Algum subtitulo com uma info bacana",
       caption = "Fonte: fonte dos dados/de quem fez") +
  geom_smooth(method = "lm", alpha = .2)  +
  stat_cor(method = "pearson", label.x = 3, 
           label.y = 10, size = 15, col = "darkgreen") +
  theme(text = element_text(size = 25)) # Vamos aumentar as fontes com um tapa no visual
g6

ggarrange(g2, g3, g4, g5) # para fazer um painel

# E ai, viu como é fácil?
# Para mais dicas, fale comigo no Twitter, Abs
# @DalsonFigueired
