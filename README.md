# Performance-Evaluation-of-Cryptographic-Algorithms
The purpose is to analyze and compare performance between encryption, decryption speed of symmetric algorithms, asymmetric algorithms and hash functions.

NOTE:

    • The code has been run on VM with JAVA version 10.
    
    • For programs, “Bouncy Castle” security provider is required.
    

## Measurements for encryption algorithm:


### 128 - bit AES Encryption/Decryption in CBC Mode: 


Key generation time: 106.9 milliseconds


Encryption time:

    • Small file: 521 microseconds
    
    • Large file: 108659 microseconds

Decryption time:

    • Small file: 475 microseconds
    
    • Large file: 84279 microseconds
    

Encryption speed:

    • Small file: 508 nanoseconds/byte
    
    • Large file: 103 nanoseconds/byte
    

Decryption speed:

    • Small file: 464 nanoseconds/byte
    
    • Large file: 80.21 nanoseconds/byte
    

### 128 - bit AES Encryption/Decryption in CTR Mode: 

Key generation time: 101.7 milliseconds

Encryption time:

    • Small file: 433 microseconds
    
    • Large file: 37906 microseconds
    

Decryption time:

    • Small file: 457 microseconds
    
    • Large file: 40020 microseconds
    

Encryption speed:

    • Small file: 422.8 nanoseconds/byte
    
    • Large file: 36.14 nanoseconds/byte
    

Decryption speed:

    • Small file: 446.2 nanoseconds/byte
    
    • Large file: 38.16 nanoseconds/byte
    

### 256 - bit AES Encryption/Decryption in CTR Mode: 

Key generation time: 116.3 milliseconds


Encryption time:

    • Small file: 463 microseconds
    
    • Large file: 40847 microseconds
    

Decryption time:

    • Small file: 526 microseconds
    
    • Large file: 32814 microseconds
    

Encryption speed:

    • Small file: 452.14 nanoseconds/byte
    
    • Large file: 38.9 nanoseconds/byte
    

Decryption speed:

    • Small file: 513.67 nanoseconds/byte
    
    • Large file: 31.2 nanoseconds/byte
    

## Measurements for hashing algorithm:

### SHA-256:

Hashing time:

    • Small file: 195 microseconds
    
    • Large file: 41135 microseconds
    

Hashing speed:

    • Small file: 190 nanoseconds/byte
    
    • Large file: 39.22 nanoseconds/byte
    

### SHA-512: 

Hashing time:

    • Small file: 1148 microseconds
    
    • Large file: 56677 microseconds
    

Hashing speed:

    • Small file:  1121.09 nanoseconds/byte
    
    • Large file: 54.05 nanoseconds/byte
    

### SHA3-256: 

Hashing time:

    • Small file: 1246 microseconds
    
    • Large file: 55354 microseconds
    

Hashing speed:

    • Small file:  1216.79 nanoseconds/byte
    
    • Large file: 52.78 nanoseconds/byte
    

### 2048 - bit RSA Encryption/Decryption: 

Key generation time: 409723.8 microseconds


Encryption time:

    • Small file: 903.2 microseconds
    
    • Large file: 705453.9 microseconds
    

Decryption time:

    • Small file: 3198.4 microseconds
    
    • Large file: 13452350.5 microseconds
    

Encryption speed:

    • Small file: 881 nanoseconds/byte
    
    • Large file: 672.77 nanoseconds/byte
    

Decryption speed:

    • Small file: 3123.04 nanoseconds/byte
    
    • Large file: 12829.16 nanoseconds/byte
    

### 3072 - bit RSA Encryption/Decryption: 

Key generation time: 1023498.8 microseconds


Encryption time:

    • Small file: 1343.9 microseconds
    
    • Large file: 9975678.7 microseconds
    

Decryption time:

    • Small file: 10314.2 microseconds
    
    • Large file: 36536782.1 microseconds
    

Encryption speed:

    • Small file: 1311.52 nanoseconds/byte
    
    • Large file: 9513.54 nanoseconds/byte
    

Decryption speed:

    • Small file: 10072.26 nanoseconds/byte
    
    • Large file: 34844.19 nanoseconds/byte
    

### 2048 - bit DSA: 

Key generation time: 94032.4 microseconds


Signing time:

    • Small file: 24032.9 microseconds
    
    • Large file: 32315.8 microseconds
    

Validation time:

    • Small file: 22987.2 microseconds
    
    • Large file: 25454.4 microseconds
    

Signing speed:

    • Small file: 23468.52 nanoseconds/byte
    
    • Large file: 30.81 nanoseconds/byte
    

Validation speed:

    • Small file: 22448.24 nanoseconds/byte
    
    • Large file: 24.27 nanoseconds/byte
    

### 3072 - bit DSA: 

Key generation time: 102468.4 microseconds


Signing time:

    • Small file: 29734.2 microseconds
    
    • Large file: 33451.3 microseconds
    

Validation time:

    • Small file: 26543.2 microseconds
    
    • Large file: 27653.1 microseconds
    

Signing speed:

    • Small file: 29037.10 nanoseconds/byte
    
    • Large file: 31.90 nanoseconds/byte
    

Validation speed:

    • Small file: 25920.89 nanoseconds/byte
    
    • Large file: 26.37 nanoseconds/byte
    

## Observed results:

    i) how per byte speed changes for different algorithms between small and large files:

    • Time to encrypt per byte decreases as the file become larger for AES and DSA algorithms. AES can handle the small and large files effectively.
    • time to hash per byte speed decreases as the file become larger for SHA hashing algorithms. This is because of the fact that hashing time is linear in the size of its input.
    • AES algorithm consumes least encryption and RSA consume longest encryption time as RSA can not encrypt data larger than key length.
    • The decryption of AES algorithm is better for larger files than other algorithms.

    ii) how encryption and decryption times differ for a given encryption algorithm:

    • Time to decrypt is smaller than the encryption for AES algorithm in CBC mode. This is because encryption is done sequentially in CBC mode while decryption can be done parallelly as the XOR step is done after the block cipher is applied.
    • Time to decrypt is comparable to the encryption for AES algorithm in CTR mode. 
    • Decryption time of the RSA algorithm takes very long time as private key involved in the decryption process is longer in comparison to the public key used in the encryption process.

    iii) how key generation, encryption, and decryption times differ with the increase in the key size.
    
    • Key generation time is increased when key size is increased from 128 to 256. 
    • Encryption time is slightly increased as the key size is increased for all the algorithms.
    • Decryption time is slightly increased as the key size is increased for all the algorithms.

    iv) how hashing time differs between the algorithms and with increase of the key size

    • SHA-256 is fastest of all followed by SHA512 and SHA3-256.
    • Hashing time increases with the increase in key size as the processing increases with the increase in key size.

    v) how performance of symmetric key encryption (AES), hash functions, and public-key encryption (RSA) compare to each other

    • The Performance of software implemented AES is comparable to hash functions. 
    • Public-key encryption (RSA) is worst for larger inputs when it is compared with the symmetric key encryption (AES).
