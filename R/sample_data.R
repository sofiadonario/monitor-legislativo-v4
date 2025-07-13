# Sample documents for fallback when database is not available
# This prevents the app from crashing

sample_documents <- data.frame(
  id = 1:5,
  titulo = c(
    "Lei Federal 14.133/2021",
    "Decreto Estadual 47.795/2020", 
    "Portaria Ministerial 1.234/2021",
    "Resolução CNJ 432/2021",
    "Medida Provisória 1.090/2021"
  ),
  tipo = c("lei", "decreto", "portaria", "resolução", "medida provisória"),
  estado = c("Federal", "São Paulo", "Federal", "Federal", "Federal"),
  estado_codigo = c("BR", "SP", "BR", "BR", "BR"),
  municipio = c("", "São Paulo", "", "", ""),
  enacting_date = as.Date(c("2021-04-01", "2020-12-15", "2021-06-20", "2021-09-10", "2021-12-30")),
  url = c(
    "https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/L14133.htm",
    "https://www.al.sp.gov.br/repositorio/legislacao/decreto/2020/decreto-47795-15.12.2020.html",
    "https://www.in.gov.br/web/dou/-/portaria-1234-2021",
    "https://atos.cnj.jus.br/atos/detalhar/4099",
    "https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/Mpv/mpv1090.htm"
  ),
  urn = paste0("urn:lex:br:federal:lei:", 1:5),
  stringsAsFactors = FALSE
)