#!/usr/bin/env python
#
# esp-idf encrypted image tool. This tool helps in generating encrypted binary image
#  and decrypting an encrypted binary image
#
# SPDX-FileCopyrightText: 2018-2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys

import rsa
from Crypto.PublicKey import RSA
from Cryptodome.Cipher import AES

esp_enc_img_magic = 0xEEBC1234

GCM_KEY_SIZE = 32
MAGIC_SIZE = 4
ENC_GCM_KEY_SIZE = 384
IV_SIZE = 16
BIN_SIZE_DATA = 4
AUTH_SIZE = 16
RESERVED_HEADER = (512 - (MAGIC_SIZE + ENC_GCM_KEY_SIZE + IV_SIZE + BIN_SIZE_DATA + AUTH_SIZE))


def generate_key_GCM(size: int) -> bytes:
    return os.urandom(int(size))


def generate_IV_GCM() -> bytes:
    return os.urandom(IV_SIZE)


def encrypt_binary(plaintext: bytes, key: bytes, IV: bytes) -> tuple:
    encobj = AES.new(key, AES.MODE_GCM, nonce=IV)
    ciphertext,authTag = encobj.encrypt_and_digest(plaintext)
    return ciphertext, authTag


def encrypt(input_file: str, rsa_key_file_name: str, output_file: str) -> None:
    print('Encrypting')
    with open(input_file, 'rb') as image:
        data = image.read()

    with open(rsa_key_file_name, 'rb') as rsa_key_file:
        rsa_key_data = rsa_key_file.read()
    rsa_key = RSA.import_key(rsa_key_data, '')
    rsa_public_key = rsa_key.publickey()
    rsa_key_file.close()

    gcm_key = generate_key_GCM(GCM_KEY_SIZE)
    iv = generate_IV_GCM()

    encrypted_gcm_key = rsa.encrypt(gcm_key, rsa_public_key)

    ciphertext, authtag = encrypt_binary(data, gcm_key, iv)

    with open(output_file, 'ab') as image:
        image.write(esp_enc_img_magic.to_bytes(MAGIC_SIZE, 'little'))
        image.write((encrypted_gcm_key))
        image.write((iv))
        image.write(len(ciphertext).to_bytes(BIN_SIZE_DATA, 'little'))
        image.write(authtag)
        image.write(bytearray(RESERVED_HEADER))
        image.write(ciphertext)


def decrypt_binary(ciphertext: bytes, authTag: bytes, key: bytes, IV: bytes) -> bytes:
    encobj = AES.new(key, AES.MODE_GCM, IV)
    plaintext = (encobj.decrypt_and_verify(ciphertext, authTag))
    return bytes(plaintext)


def decrypt(input_file: str, rsa_key: str, output_file: str) -> None:
    print('Decrypting')
    rsa_key_file = open(rsa_key, 'rb')
    rsa_key_data = rsa_key_file.read()
    rsa_key_file.close()
    rsa_key = rsa.PrivateKey.load_pkcs1(rsa_key_data, 'PEM')

    file = open(input_file, 'rb')

    recv_magic = file.read(MAGIC_SIZE)
    if(int.from_bytes(recv_magic, 'little') != esp_enc_img_magic):
        print('Error: Magic Verification Failed', file=sys.stderr)
        raise SystemExit(1)
    print('Magic Verified')

    encrypted_gcm_key = file.read(ENC_GCM_KEY_SIZE)
    gcm_key = rsa.decrypt(encrypted_gcm_key, rsa_key)

    iv = file.read(IV_SIZE)
    bin_size = int.from_bytes(file.read(BIN_SIZE_DATA), 'little')
    auth = file.read(AUTH_SIZE)

    file.read(RESERVED_HEADER)
    enc_bin = file.read(bin_size)

    decrypted_binary = decrypt_binary(enc_bin, auth, gcm_key, iv)

    file = open(output_file, 'ab')
    file.write(decrypted_binary)
    file.close()


def main() -> None:
    parser = argparse.ArgumentParser('Encrypted Image Tool')
    parser.add_argument('input_file')
    parser.add_argument('RSA_key')
    parser.add_argument('output_file_name')
    subparsers = parser.add_subparsers(dest='operation', help='run enc_image -h for additional help')
    subparsers.add_parser('encrypt', help='Encrypt an binary')
    subparsers.add_parser('decrypt', help='Decrypt an encrypted image')

    args = parser.parse_args()

    if(args.operation == 'encrypt'):
        encrypt(args.input_file, args.RSA_key, args.output_file_name)
    if(args.operation == 'decrypt'):
        decrypt(args.input_file, args.RSA_key, args.output_file_name)


if __name__ == '__main__':
    main()
