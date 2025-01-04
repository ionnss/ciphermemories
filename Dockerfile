# Usar imagem oficial do Golang
FROM golang:1.23.4

# Definir diretório de trabalho
WORKDIR /ciphermemories

# Copiar arquivos de dependências
COPY go.mod ./
COPY go.sum ./

# Baixar dependências
RUN go mod download

# Baixar o script wait-for-it
ADD https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /wait-for-it.sh

# Tornar o script executável
RUN chmod +x /wait-for-it.sh

# Copiar código-fonte
COPY . .

# Compilar aplicativo Go com otimizações para produção
RUN CGO_ENABLED=0 GOOS=linux go build -o app_ciphermemories -ldflags="-s -w"

# Expor porta 8080
EXPOSE 8080

# Comando para rodar o executável com wait-for-it
CMD ["/wait-for-it.sh", "db:5432", "--", "./app_ciphermemories"]
