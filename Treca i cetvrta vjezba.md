# Treća i četvrta laboratorijska vježba

# **TREĆA LABORATORIJSKA VJEŽBA**

Na početku vježbe smo kreirali virtualno python okruženje unutar kojeg smo instalirali cryptography biblioteku.

```powershell

C:\Users\A507>cd mjukic
C:\Users\A507\MJukic>python -m venv srp
C:\Users\A507\MJukic>cd srp
```

# Prvi izazov

U prvome izazovu smo trebali zaštititi integritet poruke koristeći MAC(Message Authenitacion Code) algoritme specifičnije koristili smo HMAC mehanizam.

1. Kreirali smo podatke u txt file-u čiji integritet ćemo zaštititi.
2. Učitali smo te podatke:

```python
from cryptography.hazmat.primitives import hashes,hmac

def main():
    with open("file.txt", "rb") as file:
        content = file.read()
        print(content)

if __name__ == "__main__":
    main()
```

1. Stvorili smo funkciju za generiranje MAC vrijednosti 

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

1. U main fji odaberemo tajnu poruku pomoću koje će se generirat ključ i skupa s fileom ju pošaljemo u fju

```python
def main():
    secret = b"super super secret"
    
    with open("file.txt", "rb") as file:
        content = file.read()
    
    mac = generate_MAC(secret, content)
    print(mac.hex())
```

1. Spremimo MAC vrijednost u file s nastavkom .sig, provjeravamo je li MAC ispravan pomoću fje verify_MAC te ispisujemo odluku fje

```python
def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True
if __name__ == "__main__":
    key = b"secret secret key"
    with open("file.txt", "rb") as file:
        content = file.read()
    
    mac = generate_MAC(key, message)
    print(mac.hex())
	
	   with open("message.sig","rb")as file:
         signature=file.read()

    is_authentic=verify_MAC(key,signature,content)
    print(is_authentic)
```

# Drugi izazov

Sa servera pomoću terminala skinemo file s našim imenom i prezimenom u kojem se nalazi 10 fileova koji predstavljaju dionice i oni imaju svoje digitalne potpise. Mi želimo utvrditi vremenski ispravnu skevencu transakcija (ispravan redosljed transakcija) sa odgovarajućim dionicama koristeći većinu već postojećeg koda iz prvog izazova. Ključ je kod ovih fileova generiran koristeći naše ime i prezime.

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    #key=b"secret secret key"
    key="jukic_marija".encode()
    path=os.path.join("challenges","jukic_marija","mac_challenge")
    print(path)
    #file_pathname=os.path.join(path,"order_1.sig")
    #print(file_pathname)
    #with open(file_pathname,"rb")as file:
       # content=file.read()
       # print(content)
    #mac=generate_MAC(key,content)
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"  
        msg_filepath=os.path.join(path,msg_filename)
        sig_filepath=os.path.join(path,sig_filename)
        with open(msg_filepath,"rb") as file:  
            message=file.read()
        with open(sig_filepath,"rb")as file:
            signature=file.read()
        is_authentic = verify_MAC(key,signature,message)

        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

```powershell
(srp) C:\Users\A507\MJukic\mjukic>python [message-integrity.py](http://message-integrity.py/)
challenges\jukic_marija\mac_challenge
Message     Buy 65 shares of Tesla (2021-11-13T17:22) NOK
Message    Sell 97 shares of Tesla (2021-11-14T20:39) NOK
Message    Sell 74 shares of Tesla (2021-11-10T11:02) NOK
Message     Buy 48 shares of Tesla (2021-11-15T12:06) NOK
Message      Buy 3 shares of Tesla (2021-11-16T00:56) OK
Message    Sell 98 shares of Tesla (2021-11-15T10:55) NOK
Message    Sell 59 shares of Tesla (2021-11-10T11:33) OK
Message     Buy 41 shares of Tesla (2021-11-10T18:58) NOK
Message     Buy 45 shares of Tesla (2021-11-10T03:05) NOK
Message    Sell 42 shares of Tesla (2021-11-14T11:13) NOK

(srp) C:\Users\A507\MJukic\mjukic>^S
```

# **DIGITAL SIGNATURE using public-key cryptography**

Ovdje smo trebali odrediti kojoj slici pripada koji digitalni potpis. Dvije slike smo skinuli sa servera kao i 2 digitalna potpisa. Jednoj od dvije slike nije pripadao niti jedan od 2 postojeća digitalna potpisa. One su potpisane privatnim ključem pošiljatelja, a mi da bismo ustvrdili koji potpis stvarno odgovara kojoj slici koristimo javni ključ pošiljatelja. S javnim ključem dekriptiramo digitalni potpis tj. file sa .sig nastavkom te onda imamo hash vrijednost koju uspoređujemo s hash vrijednošću slike. S ovime smo očuvali autenitčnost slike jer je potpisana privatnim ključem.

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
	PUBLIC_KEY_FILE = "public.pem"
	with open(PUBLIC_KEY_FILE, "rb") as f:
	PUBLIC_KEY = serialization.load_pem_public_key(
		f.read(),
		backend=default_backend())
	return PUBLIC_KEY

with open("image_2.png", "rb") as f:
	image = f.read()

with open("image_2.sig", "rb") as f:
	signature = f.read()

print(load_public_key())

def verify_signature_rsa(signature, message):
	PUBLIC_KEY = load_public_key()
	try:
		PUBLIC_KEY.verify(
			signature,
			message,
			padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)	
	except InvalidSignature:	
		return False
	else:
		return True

is_authetic = verify_signature_rsa(signature, image)

print(is_authetic)
```

# **ČETVRTA LABORATORIJSKA VJEŽBA- Password-hashing**

Zaporke, tj. lozinke su i danas najzastupljeniji način očuvanja sigurnosti informacija. Sve lozinke trebaju biti pohranjene negdje. Kako trebaju biti pohranjene negdje i kako ne bi smjele biti lako dostupne one se provlače kroz hash funkcije jer kad ih pretvorimo u hash vrijednost zbog svojsta one-way od hash fja napadači i da imaju hash vrijednost neće lako dobiti lozinku. Problem je u tome što lozinke makar su zaštićene u pohrani koristeći hash fje nisu same toliko teške za pogoditi često. Zbog toga mnogi hakeri rade predefined dictionary s najčešće korištenim lozinkama i njihovim hash vrijednostima za najčešće korištenu hash funkciju i sigurnost narušavaju brute-force napadima. Zato kako bismo očuvali integritet sustava bismo trebali koristiti salt-bits jer oni  nadodaju dodatne bitove na hash vrijednost koje je teže unaprijed definirati i tako izvršiti napad. Osim ove zaštite sa salt-bits također imamo i iterativni hashing odnosno hashiranje već prethodno hashirane vrijednosti nekoliko puta. Ova metoda oduzima puno vremena napadaču prilikom napada do mjere da se napadaču možda ne isplati pokušavati probiti do lozinke i zbog toga osigurava korisnika na temelju vremenske ekonomičnosti.Osim ove dvije metode imamo i memory-hard funkcije koje su napravljene s ciljem da zauzmu dosta rama i budu dosta sporije nego obične hash funkcije kako bi,ponovno, natjerale hakera da odustane od napada zbog neisplativosti.

Kroz ovu vježbu smo pratili vrijeme izvršavanja brzih i sporih kriptografskih hash fja.

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10)  # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "Linux CRYPT 5k",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "Linux CRYPT 1M",
            "service": lambda: linux_hash(password, rounds=10**6, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

```powershell
(MJukic) C:\Users\A507\MJukic\MJukic>python password.py
Traceback (most recent call last):
  File "C:\Users\A507\MJukic\MJukic\password.py", line 2, in <module>
    from prettytable import PrettyTable
ModuleNotFoundError: No module named 'prettytable'

(MJukic) C:\Users\A507\MJukic\MJukic>pip install prettytable
Collecting prettytable
  Using cached prettytable-2.4.0-py3-none-any.whl (24 kB)
Collecting wcwidth
  Using cached wcwidth-0.2.5-py2.py3-none-any.whl (30 kB)
Installing collected packages: wcwidth, prettytable
Successfully installed prettytable-2.4.0 wcwidth-0.2.5
WARNING: You are using pip version 21.2.3; however, version 21.3.1 is available.
You should consider upgrading via the 'C:\Users\A507\MJukic\MJukic\Scripts\python.exe -m pip install --upgrade pip' command.

(MJukic) C:\Users\A507\MJukic\MJukic>python password.py
Traceback (most recent call last):
  File "C:\Users\A507\MJukic\MJukic\password.py", line 8, in <module>
    from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2
ModuleNotFoundError: No module named 'passlib'

(MJukic) C:\Users\A507\MJukic\MJukic>pip install passlib
Collecting passlib
  Using cached passlib-1.7.4-py2.py3-none-any.whl (525 kB)
Installing collected packages: passlib
Successfully installed passlib-1.7.4
WARNING: You are using pip version 21.2.3; however, version 21.3.1 is available.
You should consider upgrading via the 'C:\Users\A507\MJukic\MJukic\Scripts\python.exe -m pip install --upgrade pip' command.

(MJukic) C:\Users\A507\MJukic\MJukic>python password.py
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000616       |
+----------+----------------------+

+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |        4e-05         |
| AES      |       0.000616       |
+----------+----------------------+

+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |       3.1e-05        |
| HASH_MD5    |        4e-05         |
| AES         |       0.000616       |
+-------------+----------------------+

(MJukic) C:\Users\A507\MJukic\MJukic>python password.py
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000628       |
+----------+----------------------+

+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |       3.8e-05        |
| AES      |       0.000628       |
+----------+----------------------+

+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |       3.3e-05        |
| HASH_MD5    |       3.8e-05        |
| AES         |       0.000628       |
+-------------+----------------------+

+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.3e-05        |
| HASH_MD5       |       3.8e-05        |
| AES            |       0.000628       |
| Linux CRYPT 5k |       0.006758       |
+----------------+----------------------+

+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.3e-05        |
| HASH_MD5       |       3.8e-05        |
| AES            |       0.000628       |
| Linux CRYPT 5k |       0.006758       |
| Linux CRYPT 1M |       1.261349       |
+----------------+----------------------+
```

Često korištena funkcija za enkripciju AES se izvršava vrlo brzo, od nje su još brže sha256 kao i nesigurna hash funkcija sklona kolizijama md5,  s druge strane npr. Linux CRYPT je funkcija kojoj treba puno vremena a pogotovo kad ima veliki broj iteracija. Ona koristi salt-bit kao i iterativni hashing i s velikim brojem iteracija npr. milijun treba joj dosta više vremena nego nekim klasičnim kriptografskim hash funkcijama. S velikim brojem iteracija moramo biti oprezni, prevelik broj iteracija bi nam mogao srušiti sustav odnosno sami bi sebi izveli DoS napad.