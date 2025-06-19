# SecretScratch

## Overview 

`SecretScratch` is a proof of concept [steganography](https://en.wikipedia.org/wiki/Steganography) tool used to embed files into scratch projects (`.sb3`files) & retrieve them. Essentially turning [scratch](hrrps://scratch.mit.edu) to a hosing platform for any type of file (be it less than 2MB).

## Installation

clone the repository

```
git clone https://github.com/DNApeople/SecretScratch.git
```

install requirements

```
pip install -r requirements.txt
```

## Usage

1. Unprotected embed

```
$ python SecretScratch.py embedd --input <secret file> --cover <cover file> --output <output file>
```

The `cover file` is generally a scratch project with multiple unattached (not attached to code blocks) comments spread across multiple sprites.

The `output file` would be the compound file of the `secret` and `cover`

2. Unprotected extract

Extract from local project file

```
$ python3 SecretScratch.py extract --local <local project> --output <extracted file> 
```

Extract file directly from uploaded project (on [scratch](https://scratch.mit.edu))

**UPLOADING SENSITIVE DATA UNENCRYPTED IS NOT RECOMMENDED**

```
$ python3 SecretScratch.py extract --webproject <project id> --output <extracted file> 
```

3. Encrypted embed

```
$ python SecretScratch.py embedd --input <secret file> --cover <cover file> --output <output file> --encrypt
```

The only difference would be the `--encrypt` flag

Once done with the decryption the token would be saved to `<cover file>.dcr.json`. The file **CAN NOT BE DECRYPTED** without the token.

4. Encrypted extract

To extract encrypted data from either local or remote files the decryption token (genarated when file was embedded) must be passed in via the `--decrypt <token>.dcr.json`

**IF YOU PLAN ON UPLOADING A FILE IT'S BEST TO ENCRYPT IT.**

## When creating a cover file, it shold have
- At least one sprite, with
- At least one comment for the sprite (not attached to code blocks).
