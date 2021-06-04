from qiskit import QuantumCircuit, Aer, assemble
from Crypto.Util.number import getRandomRange, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

qasm_sim = Aer.get_backend('qasm_simulator')
INTERCEPT = True

N = 48

class Sender:
    def __init__(self, n):
        self.n = n
        self.key = list(map(int, bin(getRandomRange(0, 2**self.n))[2:].zfill(self.n)))
        self.bases = ['X' if getRandomRange(0, 2) else 'Z' for _ in range(self.n)]
        self.secret = None
        self.enc_key = None

    def encode_message(self):
        message = []
        for i in range(self.n):
            qc = QuantumCircuit(1,1)
            if self.bases[i] == 'Z':
                if self.key[i] == 0:
                    pass 
                else:
                    qc.x(0)
            else:
                if self.key[i] == 0:
                    qc.h(0)
                else:
                    qc.x(0)
                    qc.h(0)
            message.append(qc)
        return message
    
    def reduce_key(self, foreign_bases):
        s = []
        for k, b1, b2 in zip(self.key, self.bases, foreign_bases):
            if b1 == b2:
                s.append(k)
        self.secret = int(''.join(map(str, s)), 2)
    
    def test_exposure(self, mask):
        sample = self.secret & mask
        self.secret = abs(self.secret | mask)
        return sample

class Receiver:
    def __init__(self, n):
        self.n = n
        self.bases = ['X' if getRandomRange(0, 2) else 'Z' for _ in range(self.n)]
        self.secret = None
        self.enc_key = None

    def receive_message(self, message):
        global qasm_sim
        vals = []
        for q in range(self.n):
            if self.bases[q] == 'Z':
                message[q].measure(0,0)
            else:
                message[q].h(0)
                message[q].measure(0,0)
            qop = assemble(message[q], shots=1, memory=True)
            b = int(qasm_sim.run(qop).result().get_memory()[0])
            vals.append(b)
        self.key = vals
    
    def reduce_key(self, foreign_bases):
        s = []
        for k, b1, b2 in zip(self.key, self.bases, foreign_bases):
            if b1 == b2:
                s.append(k)
        self.secret = int(''.join(map(str, s)), 2)
        self.key_len = self.secret.bit_length()

    def test_exposure(self, mask):
        sample = self.secret & mask
        self.secret = abs(self.secret | mask)
        return sample

class Interceptor:
    def __init__(self, n):
        self.n = n
        self.bases = ['X' if getRandomRange(0, 2) else 'Z' for _ in range(self.n)]
    
    def intercept_message(self, message):
        global qasm_sim
        vals = []
        for q in range(self.n):
            if self.bases[q] == 'Z':
                message[q].measure(0,0)
            else:
                message[q].h(0)
                message[q].measure(0,0)
            qop = assemble(message[q], shots=1, memory=True)
            b = int(qasm_sim.run(qop).result().get_memory()[0])
            vals.append(b)
        self.key = vals

alice = Sender(N)
bob = Receiver(N)
eve = Interceptor(N)

print ("[X] Alice key: ", alice.key)

message = alice.encode_message()

if INTERCEPT:
    print ("[X] Message intercepted by Eve")
    eve.intercept_message(message)

bob.receive_message(message)

print ("[X] Bob key: ", bob.key)

bob.reduce_key(alice.bases)
alice.reduce_key(bob.bases)

print ("[X] Common secret computed")

sample_size = 5
sample_mask = list("1"*5 + "0"*(bob.key_len-5))
random.shuffle(sample_mask)
sample_mask = int(''.join(sample_mask), 2)

alice_sample = alice.test_exposure(sample_mask)
bob_sample = bob.test_exposure(sample_mask)

if alice_sample != bob_sample:
    print ("[X] Interception detected")
else:
    print ("[X] No interception detected. Common secret established")
    print (alice.secret, bob.secret)
