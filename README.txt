-------------- ECB CIPHER MODE --------------

I have not included the ecb (electronic cookbook) modes of any of the ciphers in this program since the way it encrypts data means that two identical plaintext blocks will result in two identical ciphertext blocks - it doesn't hide patterns in the data, so it is therefore not secure enough to rely on to provide a secure protocol.

http://books.google.co.uk/books?id=WLLAD2FKH3IC&pg=PA25&lpg=PA25&dq=ecb+cipher+mode&source=bl&ots=O9GnpOmcCE&sig=cu3AKxfdizIGQtNk6kx56YlmhmU&hl=en&ei=gi9BSoWBI9CwjAep1bWRCQ&sa=X&oi=book_result&ct=result&resnum=2
(page 26)

http://msdn.microsoft.com/en-us/library/system.security.cryptography.ciphermode.aspx

http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation
(good example showing patterns being retained in encrypted pictures)

-------------- SINGLE KEY DES --------------

I have not included the single-key DES cipher because the key is too short to guarantee security.

http://www.openssl.org/docs/crypto/des.html

http://ecommerce.hostip.info/pages/288/Data-Encryption-Standard-DES.html
