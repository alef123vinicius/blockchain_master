# -*- coding: utf-8 -*-
"""
Created on Tue Oct 23 16:04:51 2018

@author: alef1
"""

import socket
import json 
import binascii
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
import random

class Transacao:
    def __init__(self, emissor, destinatario, chave_privada, data):
        self.emissor = emissor 
        self.destinatario = destinatario
        self.chave_privada = chave_privada
        self.data = data
    
    def assinar_transacao(self):
        signer = PKCS1_v1_5.new(self.chave_privada)
        h = SHA.new(str(self.mostrar_transacao()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')
    
    def mostrar_transacao(self):
        return str(self.emissor.name)+" ---> "+str(self.destinatario.name)+" : "+str(self.data)
    
    def toString(self):
        return Transacao(str(self.emissor),str(self.destinatario),str(self.chave_privada),str(self.data))
    
class Carteira:
    def __init__(self, name):
        self.name = name
        self.semente = Random.new().read
        self.chave_privada = RSA.generate(1024, self.semente)
        self.chave_publica = self.chave_privada.publickey()
        
    def criptografar(self, chave_publica, data):
        return chave_publica.encrypt(data, 32)
    
    def descriptografar(self, chave_privada, enc_data):
        return chave_privada.decrypt(enc_data)


def Main():
    
        c1 = Carteira("joao")
        c2 = Carteira("marina")
    
        host = '127.0.0.1'
        port = 5000
         
        mySocket = socket.socket()
        mySocket.connect((host,port))
         
        
        message = input(" -> ")
        while message != 'q':
            #gerando dados aleatorios para teste
            data = str(random.uniform(0,10))
            #criando a transacao
            t = Transacao(c1,c2,c1.chave_privada,data)
            #passar tudo para string e transformar em json
            j = json.dumps(t.toString().__dict__)
            #enviando mensagem
            mySocket.send(j.encode())
            #esperand oresposta do servidor 
            data = mySocket.recv(1024).decode()
            print ('Received from server: ' + data)
            message = input(" -> ")
                
        mySocket.close()
        
if __name__ == '__main__':
    Main()