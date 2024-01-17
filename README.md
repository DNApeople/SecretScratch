# SecretScratch

1. Requirements 
   Cryptodome
   ~~~
      pip install Cryptodome
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
