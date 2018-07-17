Smartcards with lit
============

This repository contains the code to a proof-of-concept using smartcards to sign requests to [lit](https://github.com/mit-dci/lit), the Lightning Network implementation worked on by [MIT's Digital Currency Initiative](https://dci.mit.edu)

## Contents

* [cardreader](cardreader/): Reads smart cards and prints out their public key
* [signoncard](signoncard/): Generates a payment request, signs it using the smart card, and then transmits it to the lit node over RPC
* [javacard-applet](javacard-applet/): The code to the javacard applet running on the smart card. 

## Note on cards

You need [JCIDE](https://www.javacardos.com/javacardforum/viewtopic.php?f=26&t=43) to build this and burn it onto a blank card like [this one](https://www.javacardos.com/store/products/10000). Any JavaCard 3.0.4 compatible smartcard will do.