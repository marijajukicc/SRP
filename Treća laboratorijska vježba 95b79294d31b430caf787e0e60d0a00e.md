# Treća laboratorijska vježba

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