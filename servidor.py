# -*- coding: utf-8 -*-
"""
Created on Tue Oct 23 16:04:50 2018

@author: alef1
"""

import socket
import json 
import binascii
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256

DIF=2
cadeia_b = []

class Bloco:
    #seria igual ao this para separar o que é parametro e o que é da classe
    def __init__(self, id, data, prev_hash):
        self.id = id
        self.nonce = 0
        self.data = data
        self.prev_hash = prev_hash
        self.hash_bloco = False
    
    def m(bloco):
        print(" ________________________________________________")
        print("| id           : "+str(bloco.id))
        print("| hash anterior: "+bloco.prev_hash[:32])
        print("| hash bloco   : "+bloco.hash_bloco[:32])
        print("| nonce        : "+str(bloco.nonce))
        print("| data         : "+str(bloco.data))
        print(" ________________________________________________")    
        
    def mostrar_bloco(self):
        return ["id: ",self.id," hash anterior: ",self.prev_hash," hash_bloco: ",self.hash_bloco," nonce: ",self.nonce," data: ",self.data]
    
    #o que chamam de minerar bloco
    def minerar_bloco(self, bloco_t, dificuldade=DIF):
        nonce = 0
        resultado_hash = '0'
        while(resultado_hash[:dificuldade] != '0'*dificuldade):
            #print("nonce: ", nonce)
            resultado_hash = gerar_hash(str(self.data)+str(self.id)+str(self.prev_hash)+str(nonce))
            if(resultado_hash[:dificuldade] == '0'*dificuldade):
                self.hash_bloco = resultado_hash
                self.nonce = nonce
            nonce = nonce + 1
    
    
    def gerar_hash(self, data):
        return SHA256.new(data.encode('utf-8')).hexdigest()
 
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
        
def criar_genesis(dif=DIF):
    c0 = Carteira("Genesis")
    if(len(cadeia_b) == 0):
        data = "10000"
        t = Transacao(c0, c0, c0.chave_privada, data)   
        bloco = Bloco(0, t.assinar_transacao(), "0"*64)
        bloco.minerar_bloco(bloco,dif)
        cadeia_b.append(bloco)

def gerar_hash(data):
        return SHA256.new(data.encode('utf-8')).hexdigest()

def verifica_mineracao(bloco):
        if(bloco.hash_bloco != False):
            if(bloco.hash_bloco[:DIF] == '0'*DIF):
                return True
            else:
                return False
        else:
            return False


def valid_chain(cadeia=cadeia_b):
    bloco_anterior = cadeia[0]
    index = 1
    
    while index < len(cadeia):
        bloco = cadeia_b[index]
        t_hash = gerar_hash(str(bloco_anterior.data)+
                            str(bloco_anterior.id)+
                            str(bloco_anterior.prev_hash)+
                            str(bloco_anterior.nonce))
        #if(bloco.prev_hash != bloco_anterior.hash_bloco):
        #    return False
        if bloco.prev_hash != t_hash:
            return False
        bloco_anterior = bloco
        index = index + 1
        
    return True

def visualizar_cadeia():
    for i in range(len(cadeia_b)):
        Bloco.m(cadeia_b[i])

def Main():
    host = "127.0.0.1"
    port = 5000
     
    mySocket = socket.socket()
    mySocket.bind((host,port))
     
    mySocket.listen(1)
    conn, addr = mySocket.accept()
    print ("Connection from: " + str(addr))
    
    while True:
            #criando a genesis caso ainda não tenha
            if(len(cadeia_b) == 0):
                criar_genesis()
            #recebendo transacao
            data = conn.recv(1024).decode()
            t = json.loads(data)
            #para acessar cada dado basta utilizar o dicionario 
            print("transacao recebida: ",t)
            #criando bloco
            bloco = Bloco(len(cadeia_b), t, cadeia_b[-1].hash_bloco)

            bloco.minerar_bloco(bloco)
            if(verifica_mineracao(bloco)):
                cadeia_b.append(bloco)
            
            visualizar_cadeia()
    
            if not data:
                    break
            print ("from connected  user: " + str(data))
            data = "transacao recebida"
            print ("sending: " + str(data))
            #enviando confirmacao
            conn.send(data.encode())
    
    conn.close()
     
if __name__ == '__main__':
    Main()