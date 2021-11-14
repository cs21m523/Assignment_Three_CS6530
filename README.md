# Assignment Three CS6530
Name: Mann Jani  
Roll Number: CS21M523

#### Compare RSA decryption time using modular exponentiation and chinese remainder theorem
See attached program program.c and executable a.exe

Program uses openssl bignum library, which is necessary to be installed on the compilation target. OpenSSL sources available at https://www.openssl.org/source/

Steps to compile: gcc -I <openssl include path> -L <openssl library path> program.c -lcrypto -static  
Steps to execute: ./a.exe
