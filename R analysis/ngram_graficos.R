# Instalar e carregar pacotes com pacman
if (!require("pacman")) install.packages("pacman")

pacman::p_load(
  ngramr,       # Acesso ao Google Books Ngram Viewer via R
  ggplot2,      # Visualização gráfica elegante e customizável
  janitor,      # Limpeza e organização de dados (ex: nomes de colunas)
  tm,           # Text mining: manipulação e pré-processamento de texto
  readr,        # Leitura eficiente de arquivos (.csv, .tsv, etc.)
  wordcloud2,   # Geração de nuvens de palavras interativas em HTML
  ggtext,
  read.csv    # recursos especiais de manipulação de texto 
)


# Opções
options(scipen = 999)

# dados

css  <- ngram(c("computational social science"), year_start = 1950)
css$tema <- "computational social science"

# Carregar pacotes necessários
if (!require("pacman")) install.packages("pacman")
pacman::p_load(ggplot2, ggtext)

# Ajustar eixo x com mais variação nos anos
ggplot(css, aes(x = Year, y = Frequency, colour = Phrase)) +
  geom_line() +
  geom_point(size = 6, alpha = 0.4) +
  theme_bw() +
  labs(
    x = "",
    y = "%",
    title = "Presença de <b><i style='color:red;'>computational social science</i></b> em livros",
    subtitle = "Estimativas do N-Gram do Google (1950 - 2022)",
    caption = "Fonte: elaboração própria a partir do pacote ngramr"
  ) +
  scale_x_continuous(breaks = seq(1950, 2022, 
                                  by = 10)) +  # define os anos no eixo x
  theme(
    legend.title = element_blank(),
    text = element_text(size = 40),
    plot.title = ggtext::element_markdown(size = 40)
  )


## Gráfico 2

transparency  <- ngram(c("transparency"), year_start = 1950)
transparency$tema <- "transparency"

reproducibility  <- ngram(c("reproducibility"), year_start = 1950)
reproducibility$tema <- "reproducibility"

df <- rbind(cps, 
            transparency,
            reproducibility)

library(dplyr)

df %>%
  filter(tema != "transparency") %>%
  ggplot(aes(x = Year, y = Frequency, colour = tema)) +
  geom_line() +
  geom_point(size = 6, alpha = 0.4) +
  theme_bw() +
  labs(
    x = "",
    y = "%",
    title = "Presença de <b><i style='color:red;'>computational social science</i></b> em livros",
    subtitle = "Estimativas do N-Gram do Google (1950 - 2022)",
    caption = "Fonte: elaboração própria a partir do pacote ngramr"
  ) +
  scale_x_continuous(breaks = seq(1950, 2022, 
                                  by = 10)) +  # define os anos no eixo x
  theme(
    legend.title = element_blank(),
    text = element_text(size = 30),
    plot.title = ggtext::element_markdown(size = 32)
  )



# Dados - Publish or Perish

css_pp <- read_csv("C:/Users/dalso/Downloads/css_publish_or_perish.csv")

css_pp <- clean_names(css_pp)

css_pp %>%
  group_by(year) %>%
  summarise(n_casos = n()) %>%
  ggplot(aes(year, n_casos)) + geom_line() +
  theme_bw() +
  labs(x = "",
       y = "Número de trabalhos",
       title = "Número de trabalhos que citam Kissinger no título (1939 - 2023)",
       subtitle = "Amostra de 970 casos",
       caption = "Fonte: elaboração própria a partir do Publish or Perish") +
  theme(text = element_text(size = 20)) 

css_pp$tema <- "computational social science"

css_pp %>%
  group_by(year, tema) %>%
  summarise(n_casos = n()) %>%
  ggplot(aes(year, n_casos, colour = tema)) +
  geom_line(colour = "blue") +
  geom_point(size = 6, alpha = 0.4, colour = "blue") +
  theme_bw() +
  labs(
    x = "",
    y = "%",
    title = "Presença de <b><i style='color:blue;'>computational social science</i></b> em obras científicas",
    subtitle = "Estimativas do Google Scholar (2001 - 2025)",
    caption = "Fonte: elaboração própria a partir do Publish or Perish"
  ) +
  scale_x_continuous(breaks = seq(2001, 2025, 
                                  by = 5)) +  # define os anos no eixo x
  theme(
    legend.title = element_blank(),
    text = element_text(size = 30),
    plot.title = ggtext::element_markdown(size = 32)
  ) +
  ylim(0, 20)

# Tabela

# Instalar e carregar pacotes necessários
if (!require("pacman")) install.packages("pacman")
pacman::p_load(gt, readr, dplyr)

css_pp_filtrada <- css_pp %>%
  select(title, year, publisher, cites) %>%
  filter(year < 2015) 
  
# Pacotes necessários
if (!require("pacman")) install.packages("pacman")
pacman::p_load(gt, dplyr, scales)

# Pacotes
if (!require("pacman")) install.packages("pacman")
pacman::p_load(gt, dplyr, scales)

# Pacotes
if (!require("pacman")) install.packages("pacman")
pacman::p_load(gt, dplyr, scales)

# Criar a tabela
tabela_gt <- css_pp_filtrada %>%
  select(title, year, publisher, cites) %>%
  filter(year < 2015) %>%
  gt() %>%
  tab_header(
    title = md("**Publicações com 'Computational Social Science' no título**"),
    subtitle = "Base extraída de publicações entre 2001 e 2014"
  ) %>%
  cols_label(
    title = "Título",
    year = "Ano",
    publisher = "Editora / Plataforma",
    cites = "Citações"
  ) %>%
  tab_style(
    style = cell_text(weight = "bold", align = "center"),
    locations = cells_column_labels(columns = everything())
  ) %>%
  cols_align(
    align = "center",
    columns = c(title, year, publisher, cites)
  ) %>%
  data_color(
    columns = cites,
    colors = scales::col_numeric(
      palette = c("#fee5d9", "#fcae91", "#fb6a4a", "#cb181d"),
      domain = NULL
    )
  ) %>%
  tab_options(
    table.font.size = px(18),
    heading.title.font.size = 20,
    heading.subtitle.font.size = 16
  )

# Exibir a tabela
tabela_gt



# Wordcloud

kissinger_corpus <- VCorpus(VectorSource(kissinger$title))

kissinger_corpus <- kissinger_corpus %>% 
  tm_map(removeNumbers) %>% 
  tm_map(removePunctuation) %>% 
  tm_map(content_transformer(tolower)) %>% 
  tm_map(removeWords, stopwords("eng"))

tdm <-TermDocumentMatrix(kissinger_corpus) %>% as.matrix()
remove(kissinger_corpus)

palavras <- sort(rowSums(tdm), decreasing = T)
remove(tdm)

df <- data.frame(palavra = names(palavras), freq = palavras)

df$peso <- df$freq/sum(df$freq)*100

df$peso <- round(df$peso, 2)

row.names(df) <- NULL

df <- df %>%
  filter(palavra != "henry")

df <- df %>%
  filter(palavra != "kissinger")

df %>% arrange(desc(peso)) %>%
  filter(peso > .5) %>%
   kbl(caption = "Tabela 1 - Top 10 palavras mais usadas nos títulos de trabalhos sobre Kissinger") %>%
  kable_styling()

wordcloud2(df, 
           size = .92, 
           shape = "oval",
           rotateRatio = 0.5, 
           ellipticity = 0.9, 
           color = "#6495ED")

