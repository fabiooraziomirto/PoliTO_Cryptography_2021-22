from Cryptodome.Util.number import getPrime
from matplotlib.pyplot import getp

n_lenght = 1024

p1 = getPrime(n_lenght)
p2 = getPrime(n_lenght)

print("p1="+str(p1))
print("p2="+str(p2))

n=p1*p2
print("n="+str(n));


phi = (p1-1)*(p2-1)

# define the public exponent
e = 65537

from math import gcd

g = gcd(e, phi);
print(g)

if g != 1:
    raise ValueError

d = pow(e, -1, phi)
print("d="+str(d))

public_rsa_key = (e, n)
private_rsa_key = (d, n)


# encryption
msg = b'This is the message to encrypt'
msg_int = int.from_bytes(msg, byteorder='big')
print("msg="+str(msg_int))

if msg_int > n-1:
    raise ValueError

C = pow(msg_int, e, n)
print("C="+str(C))

D = pow(C, d, n)
print("D="+str(D))

msg_dec = D.to_bytes(n_lenght, byteorder='big')
print("msg="+str(msg_dec))
print(msg.decode())