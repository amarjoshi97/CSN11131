# Code adapted from serval sources:
#
# GUI:
# Adapted from https://pypi.org/project/PySimpleGUI/#:~:text=PySimpleGUI%204.40.,0&text=Transforms%20the%20tkinter%2C%20Qt%2C%20WxPython,frameworks%20into%20a%20simpler%20interface.&text=By%20definition%2C%20PySimpleGUI%20implements%20a,PySimpleGUI%20and%20which%20are%20not.
#
# JWT:
# Adapted from https://pyjwt.readthedocs.io/en/latest/
#
# Fernet:
#   Adapted from https://asecuritysite.com/encryption/fer AND https://asecuritysite.com/encryption/fernet2
#   which is based on the code at https://cryptography.io/en/stable/_modules/cryptography/fernet/
#
# PASETO:
#   Adapted from https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto#:~:text=PASETO%20is%20a%20new%20specification,in%20a%20safe%2C%20tamperproof%20way.
#
#
#




##### IMPORTS ######
import sys
import os
import json
import secrets
import struct
import binascii
import base64

import argparse
from argparse import Namespace

from datetime import datetime
import time
import PySimpleGUI as sg

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import paseto

##### FUNCTIONS ######
def gui():
    layout = [  [sg.Text("Token Value :", size=(10, 1)), sg.Input(key='token_value')],
                [sg.Text("Key Value   :", size=(10, 1)), sg.Input(key='token_key')],
                [sg.Radio('Tokenise', "T", default=True, key='t'), sg.Radio('Detokneise', "T", default=False, key='d')],
                [sg.Radio('JWT', "format", default=True, key='jwt'), sg.Radio('Fernet', "format", default=False,
                                        key='fernet'), sg.Radio('PASETO',"format", default=False, key='paseto')],
                [sg.Multiline(size=(51, 15), key='output', font='courier 10', background_color='white',
                              text_color='black')],
                [sg.Button("Submit", bind_return_key=True)]
                ]

    # Create the window
    window = sg.Window("Tokenizor", layout)

    # Create an event loop
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        args = conversion(values)
        if(values['t']):
            if (values['jwt']):
                s = tokenise_jwt(args)
            elif (values['fernet']):
                s = tokenise_fernet(args)
            elif (values['paseto']):
                s = tokenise_paseto(args)
        else:
            if (values['jwt']):
                s = detokenise_jwt(args)
            elif (values['fernet']):
                s = detokenise_fernet(args)
            elif (values['paseto']):
                s = detokenise_paseto(args)
        window['output'].update(s)

    window.close()

def conversion(values):
    return Namespace(token_value=values['token_value'], token_key=values['token_key'])
# Check for format and choice appropriate function
def tokenise(args):
    if(args.format == "jwt"):
        print(tokenise_jwt(args))
    elif(args.format == "fernet"):
        print(tokenise_fernet(args))
    elif (args.format == "paseto"):
        print(tokenise_paseto(args))
    else:
        print('tokeniser.py: error: the following arguments are required: --format')
def detokenise(args):
    if (args.format == "jwt"):
        print(detokenise_jwt(args))
    elif (args.format == "fernet"):
        print(detokenise_fernet(args))
    elif (args.format == "paseto"):
        print(detokenise_paseto(args))
    else:
        print('tokeniser.py: error: the following arguments are required: --format')



######################### JWT #########################
def tokenise_jwt(args):
    token = jwt.encode({"value": args.token_value},args.token_key , algorithm="HS256")
    t = jwt_get(token)
    return pretty_jwt("Tokenising", token,args.token_value, args.token_key, header=t[0],
                             payload=t[1], sign=t[2], detoken=True)

def detokenise_jwt(args):
    try:
        value = jwt.decode(args.token_value, args.token_key, algorithms=["HS256"])
        t = jwt_get(args.token_value)
        return pretty_jwt("Detokenising", args.token_value, value['value'], args.token_key, header=t[0],
                             payload=t[1], sign=t[2])
    except Exception as e:
        return (e)

def jwt_get(token):
    if isinstance(token, bytes):
        t = token.decode("utf-8") .split(".")
    else:
        t = token.split(".")
    return t

def pretty_jwt(format, token, value, key, time=None, header='None', payload='None', sign='None', detoken=False):
    s = "===================================================" + '\n'
    s = s + "Type: JWT - HS256 - " + format + '\n'
    if isinstance(value, bytes):
        s = s + "Value:\t " + value.decode('utf-8') + '\n'
    else:
        s = s + "Value:\t " + value + '\n'
    if isinstance(key, bytes):
        s = s + "Secret Key:\t " + key.decode('utf-8') + '\n'
    else:
        s = s + "Secret Key:\t " + key + '\n'
    s = s + "===================================================" + '\n'
    if isinstance(token, bytes):
        s = s + "Token:\t " + token.decode('utf-8') + '\n'
    else:
        s = s + "Token:\t " + token + '\n'
    s = s + "===================================================" + '\n'
    now = datetime.now()
    ctime = now.strftime("%m/%d/%Y, %H:%M:%S")
    s = s + "Current-Time:\t  " + ctime + '\n'
    s = s + "===================================================" + '\n'
    if(detoken):
        s = s + "Token Structure" + '\n'
        s = s + "Header:\t " + header + '\n'
        s = s + "Payload:\t " + payload + '\n'
        s = s + "Signature:\t " + sign + '\n'
        s = s + "===================================================" + '\n'
    return s






######################### Fernet #########################
def tokenise_fernet(args):
    key = generate_key(args.token_key, size=32, encode=True)
    f = Fernet(key)
    token = f.encrypt(args.token_value.encode())
    return pretty_fernet("Tokenising", token, args.token_value, key, detoken=True)

def detokenise_fernet(args):
    key = generate_key(args.token_key, size=32, encode=True)
    f = Fernet(key)
    value = f.decrypt(args.token_value.encode())
    return pretty_fernet("Detokenising", args.token_value, value, key)

def pretty_fernet(format, token, value, key, detoken=False):
    if not isinstance(token, bytes):
        decoded_token = token
    else:
        decoded_token = token.decode('utf-8')
    s = "===================================================" + '\n'
    s = s + "Type: Fernet - " + format + '\n'
    if isinstance(value, bytes):
        s = s + "Value:\t" + value.decode('utf-8') + '\n'
    else:
        s = s + "Value:\t" + value + '\n'
    if isinstance(key, bytes):
        s = s + "Secret Key:\t" + key.decode('utf-8') + '\n'
    else:
        s = s + "Secret Key:\t" + key + '\n'
    s = s + "===================================================" + '\n'
    s = s + "Encode Token:\t" + decoded_token + '\n'

    if(detoken):
        s = s + "===================================================" + '\n'
        now = datetime.now()
        now = now.strftime("%m/%d/%Y, %H:%M:%S")
        s = s + "Current-Time:\t " + now + '\n'
        s = s + "Time stamp:\t" + (token[2:18]).decode('utf-8') + '\n'
        s = s + "===================================================" + '\n'
        s = s + "\nVersion:\t" + (token[0:2]).decode('utf-8') + '\n'
        s = s + "IV:\t\t" + (token[18:50]).decode('utf-8') + '\n'
        s = s + "HMAC:\t\t" + (token[-64:]).decode('utf-8') + '\n'
    s = s + "===================================================" + '\n'
    return s

######################### PASETO #########################
def tokenise_paseto(args):
    key = generate_key(args.token_key, size=32, encode=False)
    data={"value": args.token_value}
    token = paseto.create(
        key=key,
        purpose='local',
        claims= data,
        footer={
            'id': '12345'
        },
        exp_seconds=10*60
    )
    t = pase_get(token)
    return pretty_pase("Tokenising", token, args.token_value, args.token_key, detoken=True, version=t[0],
                       purpose=t[1], payload=t[2], footer=t[3])

def detokenise_paseto(args):
    key = generate_key(args.token_key, size=32, encode=False)
    token = paseto.parse(
        key=key,
        purpose='local',
        token=args.token_value.encode()
    )

    return pretty_pase("Detokenising", args.token_value, token, args.token_key)

def pretty_pase(format, token, value, key, version='None', purpose=None, payload='None', footer='None', \
                                                                                          detoken=False):
    timestamp=None
    if(not detoken):
        print(value)
        message=value['message']
        value = message['value']
        timestamp = message['exp']
        footer = value[1]


    s = "===================================================" + '\n'
    s = s + "Type: Fernet - " + format + '\n'
    if isinstance(value, bytes):
        s = s + "Value:\t " + value.decode('utf-8') + '\n'
    else:
        s = s + "Value:\t " + value + '\n'
    if isinstance(key, bytes):
        s = s + "Secret Key:\t " + key.decode('utf-8') + '\n'
    else:
        s = s + "Secret Key:\t " + key + '\n'
    s = s + "===================================================" + '\n'
    if isinstance(token, bytes):
        s = s + "Token:\t " + token.decode('utf-8') + '\n'
    else:
        s = s + "Token:\t " + token + '\n'
    s = s + "===================================================" + '\n'
    now = datetime.now()
    ctime = now.strftime("%m/%d/%Y, %H:%M:%S")
    s = s + "Current-Time:\t " + ctime + '\n'
    if(timestamp):
        s = s + "Timestamp:\t  " + timestamp + '\n'
    s = s + "===================================================" + '\n'
    if(detoken):
        s = s + "Token Structure" + '\n'
        s = s + "Version:\t " + version + '\n'
        s = s + "Purpose:\t " + purpose + '\n'
        s = s + "Payload:\t " + payload + '\n'
        s = s + "Footer:\t " + footer + '\n'
        s = s + "===================================================" + '\n'
    return s
def pase_get(token):
    if isinstance(token, bytes):
        t = token.decode("utf-8") .split(".")
    else:
        t = token.split(".")
    return t


######################### Key Generation Function #########################
def generate_key(k, size=32, encode=False):
    salt="0000000000000000".encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=size, iterations=100, salt=salt, backend=default_backend())
    key = (kdf.derive(k.encode()))
    if(encode):
        key = base64.urlsafe_b64encode(key)
    return key



##### MAIN ######
#Create Agrument Parser
parser = argparse.ArgumentParser(description='Tokenizes and detokenises tokens. Supporting token formats include, '
                                             'JWT, Fernet and paseto.')

parser.add_argument('token_value',
                    action='store_const',
                    metavar='V',
                    help='token value',
                    const="secret message")
parser.add_argument('token_key',
                    action='store_const',
                    metavar='K',
                    help='token key, used to sign/encrypt the token',
                    const="password")

group = parser.add_mutually_exclusive_group()
group.add_argument("-t", "--tokenise",
                   action="store_false",
                   help='Set to tokenise')
group.add_argument("-d", "--detokenise",
                   action="store_true",
                   help='Set to detokenise')

parser.add_argument('--format',
                    choices=['jwt', 'fernet', 'paseto'],
                    help='Select token format, either JWT, Fernet or Paseto')
parser.add_argument("-i", "--interface",
                   action="store_true",
                   help='Use to open tokeniser interface')

# parse arguments and store in args
args = parser.parse_args()

#Check if tokenising to detokenising
if(args.interface):
    gui()
elif(args.tokenise):
    #tokenise(args)
    pass
elif(args.detokenise):
    #detokenise(args)
    pass
else:
    print('tokeniser.py: error: the following arguments are required: -t or -d')
