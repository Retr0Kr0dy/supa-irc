Supa-IRC
======= 

Supa-IRC is an CLI encrypted chat over TCP using RSA and AES (yes it should be TLS but lemme do my stuff). 

IRC (Internet Relay Chat) are text-based chat system for instant messaging. They are not used that much nowaday, but they still are good coding challenge or old dad jokes.

I know it's dumb, but I have to say it, it <span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;">is not</span></span></span></span></span>
safe for use, encryption can be f?cked up, so, don't trust this script as unbreakable and don't send nuclear code or any other confidential data over Supa-IRC. 😁


![Alt Text](https://giffiles.alphacoders.com/212/212812.gif)


# Summary 

- [INSTALLATION]()
    - [Requierements]()
    - [Docker]()
- [USAGE]()
    - [Options]()
    - [Usage]()
- [HOW IT WORK ?!]()
- [VERSION]()
    - [0.x.x-alfa]()
    - [1.x.x]()


# INSTALLATION

## Requierements
    
- [python3.10]()
- [cryptography]()
- [pycryptodome]()
    
## Docker

### Build 

```sh
docker build -t supa-irc:v0.1 -f docker/Dockerfile
```

###  Test 
To test it within docker, use the following command :

```sh
docker run -it -w /work -v ${PWD}:/work supa-irc:v0.1
```


# USAGE

## Options

| Name | Description | Action |
|------|-------------|--------|
|--server, -s | Host server| Store True |
|--client, -c | Connect to server| Store True |
|--address, -a | Addess to use | Get address |
|--port, -p | Port to use | Get port |
|--nickname, -n | Nickname to use | Get nickname |


## Usage

### Server

`python3.10 ./supa-irc.py -s -a <address to use > -p <port to use>`

### Client

`python3.10 ./supa-irc.py -c -a <address of server> -p <port of server> -n <nickname to use>`



# HOW IT WORK ?!

blablabla

# VERSION

## 0.x.x-alfa

0.x.x-afla releases are not fully usable, be careful when using those, you may encounter some problems (like flood your network, flood you memory, etc...)

## 1.x.x

### NOT RELEASED FOR NOW
