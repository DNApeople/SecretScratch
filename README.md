# SecretScratch

1. Requirements 
   Cryptodome
   ~~~
   $ pip install pycryptodome
   ~~~

3. Usage

   python SecretScratch.py -h
   ~~~~~~
   usage: SecretScratch.py [-h] (-em EMBED | -ex) -i INPUT -o OUTPUT [-enc | -dec DECRYPT]

   SecretScratch file embeder/extractor.

   options:
           -h, --help            show this help message and exit
           -em EMBED, --embed EMBED
                                 File to be embeded.
           -ex, --extract        extract from <input.sb3>
           -i INPUT, --input INPUT
                                 Scratch .sb3 file.
           -o OUTPUT, --output OUTPUT
                                 Output file (Can be used with -em/--embed & -ex/--extract)
           -enc, --encrypt       Encrypt embeding data
           -dec DECRYPT, --decrypt DECRYPT
                                 Decrypt extracted data (-dec/--decrypt <keys.json>)
   ~~~~~~

4. Examples
   
   i. Normal embed
   ~~~
   $ python SecretScratch.py --embed embed_this_secret.txt --input input_file.sb3 --output output_file_with_secret.sb3 
   ~~~
   ii. Normal extract
   ~~~
   $ python SecretScratch.py --extract --input file_with_secret.sb3 --output extracted_file.txt 
   ~~~
   
   iii. Encrypted embed (recommended)
   ~~~
   $ python SecretScratch.py --embed embed_this_file.txt --encrypt --input input_file.sb3 --output output_file_with_encrypted_secret.sb3
   ~~~
      [+] Decrypt token => input_file.dec.json
   vi. Decrypt encrypted embed & extract.
   ~~~
   $ python SecretScratch.py --extract --decrypt decrypt_token.dec.json --input file_with_encrypted_secret.sb3 --output secret.txt
   ~~~

5. What you must consider.

   . The .sb3 file used for embedding the secret must have an adequate number of "in project comments" (more than a 100).
      Which I tried to automate but scratch just keeps rejecting them unless manually added.
      The "test.sb3" already has a 100 comment headstart, so use that & add to it.
   . When adding comments they must be spread across multiple sprites, because scratch Dosen't allow toomany comments in a single sprite
      
