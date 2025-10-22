# Scanner sieťových služeb

Jednoduchý TCP, UDP skener v C++, ktorý oskenuje zadanú IP adresu a porty. Na výstup vypíše v akom stave sa porty nachádzajú(otvorený,filtrovaný,uzavrený).


## Predpoklady

Predpokladá sa OS založený na linuxe a pred spustením je potrebné naištalovať prekladač g++ a knižnicu libpcap príkazmi:

```
sudo apt install g++
sudo apt-get install libpcap-dev
```

## Spustenie 

Najskôr je potrebné program preložiť príkazom:

```
make
```

A potom spustiť príkazom:

```
./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]
```

Kde volitľné parametre sú:
```
-i <interface> : kde argument predstavuje identifikátor rozhrania, inak sa vyberie prvý interface s neloopbackovou IP adresou
```
Povinné parametre sú:
```
[<domain-name> | <IP-address>] : doménové meno alebo IP adresa skenovaného stroja
```
Parametre z ktorých aspoň 1 musí byť zadaný:
```
-pt <port-ranges> : rozsah alebo jednotlivé porty, ktoré sú oskenované pomocou TCP
-pu <port-ranges> : rozsah alebo jednotlivé porty, ktoré sú oskenované pomocou UCP
```


## Autor

* **Marek Lörinc** 
