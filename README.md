Supa-IRC
======= 

### [Remember to check the Wiki !](https://github.com/Retr0Kr0dy/supa-irc/wiki/Supa-IRC-Wiki)

Supa-IRC is an CLI encrypted chat over TCP using RSA and AES (yes it should be TLS but lemme do my stuff). 

IRC (Internet Relay Chat) are text-based chat system for instant messaging. They are not used that much nowaday, but they still are good coding challenge or old dad jokes.

I know it's dumb, but I have to say it, it <span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;"><span style="font-size:larger;">is not</span></span></span></span></span>
safe for use, encryption can be f?cked up, so, don't trust this script as unbreakable and don't send nuclear code or any other confidential data over Supa-IRC. 😁


![Alt Text](https://giffiles.alphacoders.com/212/212812.gif)


# Summary 

- [INSTALLATION](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#installation)
    - [Requierements](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#requierements)
    - [Docker](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#docker)
- [USAGE](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#usage)
    - [Options](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#options)
    - [Usage](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#usage-1)
- [HOW IT WORK ?!](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#how-it-work-)
- [VERSION](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#version)
    - [0.x.x-alfa](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#0xx-alfa)
    - [1.x.x](https://github.com/Retr0Kr0dy/supa-irc/blob/main/README.md#1xx)


# INSTALLATION

## Requierements
    
- [python3.10](https://www.python.org/downloads/release/python-3100/)
- [cryptography](https://pypi.org/project/cryptography/)
- [pycryptodome](https://pypi.org/project/pycryptodome/)
    
## Docker

### Build 

```sh
docker build -t supa-irc:<version tag> -f docker/Dockerfile
```

###  Test 
To test it within docker, use the following command :

```sh
docker run -it -w /work -v ${PWD}:/work supa-irc:<version tag>
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

`python supa-irc.py -s -a <address to use > -p <port to use>`

### Client

`python supa-irc.py -c -a <address of server> -p <port of server> -n <nickname to use>`



# HOW IT WORK ?!

blablabla

### [Remember to check the Wiki !](https://github.com/Retr0Kr0dy/supa-irc/wiki/Supa-IRC-Wiki)

# VERSION

## 0.x.x-alfa

0.x.x-afla releases are not fully usable, be careful when using those, you may encounter some problems (like flood your network, flood you memory, etc...)

## 1.x.x

#### NOT RELEASED FOR NOW
