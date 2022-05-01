# Segurança Computacional - Trabalho 2

## Alunos

- Artur Filgueiras Scheiba Zorron - 180013696
- Brenno Pereira Cordeiro - 190127465

## Descrição

O segundo trabalho da disciplina consiste em implementar os algoritmos de AES-CTR e RSA. AES-CTR é um algoritmo de cifração simétrica, que é utilizado para cifrar mensagens. A chave de cifração AES-CTR é um vetor de 16 bytes, que é gerado aleatoriamente. A cifração AES-CTR é implementada utilizando o algoritmo de substituição de bytes. Ele funciona gerando bits aleatórios com a chave de cifração e o vetor inicial. Com esses bits é então feita a operação XOR com a string recebida. Isto cria um texto aleatório. Para decifrar precisamos apenas aplicar operações XOR com o texo usando os mesmos bits aleatórios que foram gerados na cifração usando a chave e o vetor inicial. RSA é um algoritmo de cifração assimétrica, que é utilizado para cifrar mensagens. A chave de cifração RSA é gerada aleatoriamente. A cifração RSA é implementada utilizando o algoritmo de exponenciação modular.

## Algoritmos

### AES

    - Deriva o conjunto de chaves das rodadas da chave de cifra
    - Inicializa o array de estado com os dados do bloco (texto simples)
    - Adiciona a chave da rodada inicial à matriz de estado inicial
    - Execute nove rodadas de manipulação do estado
    - Cada rodada:
        - Substitua os bytes
        - Arraste os bytes
        - Misture as colunas
        - Execute XOR com a chave da rodada
    - Realize a décima e última rodada de manipulação do estado

### RSA

    - Gera chaves pública e privada aleatórias
        - Escolhe dois primos distintos `p` e `q`
        - Calcula `n = pq`
        - Calcula `phi(n) = (p-1)(q-1)`
        - Escolhe um número aleatório `e` entre 1 e `phi(n)`
        - Calcula `d = e^-1 mod phi(n)`
    - Cifra o texto simples
        - Transmite a chave pública
        - Envia a mensagem como um bloco de 64 bytes
        - Recebe a mensagem cifrada como um bloco de 64 bytes
    - Decifra o texto cifrado
        - Recupera mensagem m a partir da chave privada 
            - `m = c^d (mod n)`
        - Decifra a mensagem m

## Implementação

`./main.py genkeys`

Gera as chaves pública e privada.

`./main.py cipher -f <file>`

Cifra arquivo <file> utilizando a chave pública gerada anteriormente.

`./main.py decipher -f <ciphered_file> -o <target_file>`

Decifra arquivo <ciphered_file> utilizando a chave privada gerada anteriormente.
