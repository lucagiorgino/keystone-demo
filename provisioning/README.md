# Client Provisioning

This file `provision.c` can be used to generate a new `test_client_key.h`, which will contain the root key pair, the client key pair and the signature of the client public key made by the system administrator with its secrey key. 

It could be modified to meet your purposes (for example to generate more client key pairs and signatures or to use a fixed root key).
The program uses `libsodium` to generate an Ed25519 key pair for the system administrator. Then will generate another Ed25519 key pair for the client and the public part will be signed with the system administrator key pair. The server will use the system administrator public key to authenticate that the client is part of the system administrator network.
 
Once `libsodium`  has been installed, compile `provision.c`, run it and redirect the output to a file with name `test_client_key.h`. 
The file `test_client_key.h` is already present in the `include` folder, but it may be necessary to generete a new one and it can be done with the following commands. 

```
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout 4917510626c55c1f199ef7383ae164cf96044aea
./configure
make && make check
sudo make install
sudo ldconfig

cd keystone-demo/provisioning
gcc -o provision provision.c -lsodium

./provision > ../include/test_client_key.h
```