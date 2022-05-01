# Segurança Computacional - Trabalho 2

## Alunos

- Artur Filgueiras Scheiba Zorron - 180013696
- Brenno Pereira Cordeiro - 190127465

## Descrição

O segundo trabalho da disciplina consiste em implementar os algoritmos de AES e RSA. AES é um algoritmo de criptografia simétrica, que é utilizado para criptografar mensagens. A chave de criptografia AES é um vetor de 16 bytes, que é gerado aleatoriamente. A criptografia AES é implementada utilizando o algoritmo de substituição de bytes. RSA é um algoritmo de criptografia assimétrica, que é utilizado para criptografar mensagens. A chave de criptografia RSA é gerada aleatoriamente. A criptografia RSA é implementada utilizando o algoritmo de exponenciação modular.

## Implementação

`./main.py genkeys`

Gera as chaves pública e privada.

`./main.py cipher -f <file>`

Cifra arquivo <file> utilizando a chave pública gerada anteriormente.

`./main.py decipher -f <ciphered_file> -o <target_file>`

Decifra arquivo <ciphered_file> utilizando a chave privada gerada anteriormente.
