# Encrypted Chat Server

This is a chat program using TCP sockets that involves a single server that can handle multiple clients interacting with eachother.

When a client connects to the server, the client sends its symmetric key encrypted with the servers public RSA key and then the server recieves the key and decrypts using its own RSA private key. Now any message sent to the server from the client is encrypted and decrypted using that symmetric key. Once the keys are established, the client will be asked for a username that will be sent to the server and stored. The client is ready to chat.

The client has a variety of options to interact with the server:
* Broadcasting: the client can send a message to all other connected clients
* Send a message to a certain individual
* Request a list of all clients connected
* Request to become an administrator for the server
* Change username


