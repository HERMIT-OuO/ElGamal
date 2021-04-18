import random
import math
from Crypto.Util.number import inverse


class PrivateKey(object):
    p = 0
    g = 0
    x = 0

    def __init__(self, p=None, g=None, x=None):
        self.p = p
        self.g = g
        self.x = x


class PublicKey(object):
    p = 0
    g = 0
    y = 0

    def __init__(self, p=None, g=None, y=None):
        self.p = p
        self.g = g
        self.y = y


# computes base^exp mod modulus
def mod_exp(base, exp, modulus):
    return pow(base, exp, modulus)


def generate_keys():
    p = 19
    g = 13
    x = random.randint(2, p - 2)
    y = g ^ x % p
    public_key = PublicKey(p, g, y)
    private_key = PrivateKey(p, g, x)
    return {'publicKey': public_key, 'privateKey': private_key}


def encode(public_key, private_key, number):
    k = random.randint(2, public_key.p - 2)
    c1 = pow(public_key.g, k, public_key.p)
    c2 = (number * pow(public_key.y, k, public_key.p)) % public_key.p
    return c1, c2


def decode(private_key, c1, c2):
    s = pow(c1, private_key.x, private_key.p)
    m = (c2 * inverse(s, private_key.p)) % private_key.p
    return m


if __name__ == '__main__':
    obj = generate_keys()
    num = 10
    c1, c2 = encode(obj["publicKey"],obj["privateKey"], num)
    print(c1, c2)
    m = decode(obj["privateKey"], c1, c2)
    print(m)
