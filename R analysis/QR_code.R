
# Esse script vai te ajudar a fazer QR codes no R.
# O procedimento é super simples, basta seguir o passo a passo
# Vamos nessa?


# Primeiro passo é instalar o pacote "qrcode", como descrito na linha 8
install.packages("qrcode")
library(qrcode) # Depois disso, vamos carregar o pacote com o comando library

# Feito isso, o R já está pronto para gerar o QR code.
# Basta agora voce usar a função qt_code, como descrito na linha 13
code <- qr_code("https://meet.google.com/qth-pwcf-vwz")

# Pegue o seu link de interesse e coloque entre aspas
# Depois disso, vamos usar a função plot para gerar o gráfico!
plot(code)

# Você pode salvar em formato de figura com esse outro comando

generate_svg(code, filename = "C:/Users/dalso/Downloads/qr.svg")

# Viu como é fácil?
# Agora tente fazer com alguma coisa do seu interesse
# Qualquer dúvida, fala comigo! Abs,
# @DalsonFigueired
