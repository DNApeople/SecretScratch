# SecretScratch

_Inspired by Steghide tool_

1. Requirements 
   Cryptodome
   ~~~
   pip install -r requirements.txt
   ~~~

3. Usage

   https://github.com/DNApeople/SecretScratch/assets/112553123/4ac45935-cc1c-498c-a102-f7fc95533abc

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
      [+] Decrypt token => input_file.sb3.dcr.json
   
   vi. Extract & decrypt
   ~~~
   $ python SecretScratch.py --extract --decrypt decrypt_token.dec.json --input file_with_encrypted_secret.sb3 --output secret.txt
   ~~~

   __(+) Now upload the file to scratch & now you have some free cloud storage.__

6. What you must consider.

   [=] The .sb3 file used for embedding the secret must have an adequate number of "in project comments" (more than a 100).
      Which I tried to automate but scratch just keeps rejecting them unless manually added.
      The "test.sb3" already has a 100 comment headstart, so use that & add to it.
   
   [=] When adding comments they must be spread across multiple sprites, because scratch Dosen't allow toomany comments in a single sprite

   [=] This method dosen't support large files as it is impractical to add thousands of comment boxes manually (but nothing stops you from trying)

   [=] __Don't attach comments to blocks, insted meke them for the sprite__ (example : test/test.sb3 has example comments)

      
