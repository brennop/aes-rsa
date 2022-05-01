#!/usr/bin/python3

import argparse
import os
import base64

import rsae
import aes

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["genkeys", "cipher", "decipher"])

    # genkeys
    parser.add_argument("--private", "-s", default="private.key")
    parser.add_argument("--public", "-p", default="public.key")

    parser.add_argument("--file", "-f")
    parser.add_argument("--output", "-o")

    parser.add_argument("--key", "-k", default="session_key.txt")
    parser.add_argument("--signature", "-c", default="signature.txt")

    args = parser.parse_args()

    if args.action == "genkeys":
        public_key, private_key = rsae.gen_keys()

        n, e = public_key
        _, d = private_key

        with open(args.private, "w") as file:
            file.write("{}\n{}".format(n, d))

        with open(args.public, "w") as file:
            file.write("{}\n{}".format(n, e))
    
    if args.action == "cipher":
        key = os.urandom(16)
        iv = os.urandom(16)
        
        session_key = key + iv
        
        # obter as chaves do rsae dos arquivos
        with open(args.private, "r") as file:
            n = int(file.readline())
            d = int(file.readline())
            private_key = (n, d)

        with open(args.public, "r") as file:
            n = int(file.readline())
            e = int(file.readline())
            public_key = (n, e)

        cipher_session_key = rsae.cipher(public_key, session_key)
        
        with open(args.file, "rb") as file:
            content = file.read()
            cipher_content = aes.ctr(content, key, iv)

            signature = rsae.sign(private_key, content)
            
        with open(args.file + ".aes", "wb") as file:
           file.write(cipher_content)
        
        with open(args.signature, "w") as file:
            file.write(base64.b64encode(signature).decode("ascii"))
            
        with open(args.key, "w") as file:
            file.write(base64.b64encode(cipher_session_key).decode("ascii"))
    
    if args.action == "decipher":
        with open(args.signature, "r") as file:
            signature = base64.b64decode(file.read())
            
        with open(args.key, "r") as file:
            cipher_session_key = base64.b64decode(file.read())

        # obter as chaves do rsae dos arquivos
        with open(args.private, "r") as file:
            n = int(file.readline())
            d = int(file.readline())
            private_key = (n, d)

        with open(args.public, "r") as file:
            n = int(file.readline())
            e = int(file.readline())
            public_key = (n, e)
        
        session_key = rsae.decipher(private_key, cipher_session_key)
        key, iv = session_key[:16], session_key[16:]

        with open(args.file, "rb") as file:
            cipher_content = file.read()
            content = aes.ctr(cipher_content, key, iv)

            result = rsae.verify(public_key, content, signature)

        if result == True:
            print("Signature ok")
            with open(args.output, "wb") as file:
                file.write(content)



