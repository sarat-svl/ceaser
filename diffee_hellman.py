from random import randrange, getrandbits
import random
import math
# A function to print all prime factors of
# a given number n


#-----------------CEASER CIPHER TABLE------------------

characters = [' ','A','B','C','D', 'E', 'F', 'G', 'H', 'I', 'J','K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T' ,'U' ,'V','W', 'X', 'Y', 'Z', ',' , '.' , '?' , '0' , '1' , '2' , '3' , '4' , '5' ,'6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!']

numbers = list(range(67))

encrypt = dict( zip ( characters , numbers ) )

decrypt = dict( zip ( numbers ,characters ) )

#--------------------------------------------------------

def primeFactors(n):

    factors = []
    # Print the number of two's that divide n
    while n % 2 == 0:
        factors.append(2)
        n = n / 2

    # n must be odd at this point
    # so a skip of 2 ( i = i + 2) can be used
    for i in range(3,int(math.sqrt(n))+1,2):

        # while i divides n , print i ad divide n
        while n % i== 0:
            factors.append(int(i))
            n = n / i

    # Condition if n is a prime
    # number greater than 2
    if n > 2:
        factors.append(int(n))

    return factors

# Generating a primitive root for a prime number(n):
# 1. Find prime factors for n-1
# 2. For every prime factor q,
#       -> check if g^(n-1)/q mod n != 1
# 3. If the above test satisfies for all prime factors of n-1, then
#    g is a primitive root of n; otherwise, not

def generator(modulus):

    # Getting all prime factors
    prime_factors = primeFactors(modulus-1)

    # consider a generator from 2 to n
    for gen in range(2,modulus):
        flag = 0

        # checking whether it satisfies  g^(n-1)/q mod n != 1
        for q in prime_factors:
            if(pow(gen,int((modulus-1)/q),modulus) != 1):
                flag = 1
            else:
                flag = 0
                break
        if(flag == 1):
            return gen
def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True
def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p
def generate_prime_number(length):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in          bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

#Fast exponentiation algorithm
def fea(g,e,n):
    #Binary format of e
    b = bin(e)[2:]
    y = g
    k = len(b) #Length of bits
    for i in range(1,k):
        # since msb is 1
        y = ( y * y ) % n
        #If the current bit is one then we multiply 'g' with resultant value
        if(b[i] == '1'):
            y = ( y * g ) % n
    return y


def Diffee():
    #Select a random prime number
    n = generate_prime_number(32)

    #select primitive root for prime number n
    g = generator(n)

    #<g,n> is public
    print("<g , n> : "+"< "+str(g)+" , "+str(n)+" >")

    return g,n

#Given plain text and key, it will perform ceaser cipher encryption and return cipher text

def ceaser_cipher_encrypt(plain_text, key):
    cipher_text = ""
    for letter in plain_text:
        cipher_text+=decrypt[(encrypt[letter] + key) % 67]
    return cipher_text

#Given cipher text and key, it will perform ceaser cipher decryption and return plain text

def ceaser_cipher_decrypt(cipher_text, key):
    plain_text = ""
    for letter in cipher_text:
        plain_text+=decrypt[(encrypt[letter] - key) % 67]
    return plain_text





#------------FOR TESTING PURPOSE-------------
def Diffie_Hellman_key():
    #Select a random prime number
    n = generate_prime_number(32)

    #select primitive root for prime number n
    g = generator(n)

    #<g,n> is public
    print("<g , n> : "+"< "+str(g)+" , "+str(n)+" >")
    A_pr = random.randint(1,n)
    B_pr = random.randint(1,n)

    A_B = fea(g,A_pr,n) #alice sends g^(Alice pr key) mod n
    print("Alice ---> Bob : ",A_B)

    B_A = fea(g,B_pr,n) ##bob sends g^(Bob pr key) mod n
    print("Bob -----> Alice : ",B_A)

    Final_Alice_key = fea(B_A,A_pr,n) #Alice calculates B_A^(Alcie pr key) mod n
    print("Final key for Alice : ",Final_Alice_key)

    Final_Bob_key = fea(A_B,B_pr,n) #Bob calculates A_B^(Bob pr key) mod n
    print("Final key for Bob : ",Final_Bob_key)
