
Maybe keep users and rooms unsorted, and add them to list and then sort that
list when giving list of names

XX XX XX XX  -> First 8 bytes are message length (it seems excluding header 
                and including the other length bytes and the error byte for 9a)
04 17        -> Next two seem to always be 04 17
XX           -> Next two seem to be the instruction code (IC): as follows

switch (IC) // ASterisks indicate from server

case 9b: Client connect to server request. All 2d following bytes are "A long time ago..."
Server responds with 9a 00 XX username, where XX is username length and the appropriate header
stuff before 9a

case 9a*: Server response to client connect request with username (starts from rand0 and increases). has 00, then username. First message length seems to be null byte + username len.
Actually, seems to be all overhead server responses. It seems the 00 is for if client
request was carried out and 01 if there was an error. For instance, if nickname belongs
to someone else, responds with 04 17 9a 01 and then the fixed length message. OG message len
seems to include error byte in len.

case 13: Client sending to avoid timeout? Followed by XX (one byte) to indicate size of 
heartbeat (possibly?) message and then the message. Seems to always be 1f bytes and "stayin
alive..." (check time to see how often it's sent). Doesn't look like server responds. Seems to
be sent every 6 seconds (starting from the time the connection is established back at client)
unless server sends something (possibly? or maybe it's client that does), and then it starts
again 6 seconds from when it received the server response or a message from someone
else. Seemed to avoid heartbeat even when got direct message error respons (nick ddin't exist).
Server seems to disconnect after 30 seconds of not receiving heartbeat (or anything else) without
sending a message. Server seems to send a 9a 03 if it's been 20 seconds without hearing anything and then it gets something, it'll send the 9a 03 along with it.

case 0f: Client update nickname request. XX to indicate nickname len, and then nickname. Seems
client takes care of ensuring correct name len.
Server responds with 9a 00 if worked and 9a 01 XX err_message if it didn't. Seems to just
update if ask to update to same name for same client.

case 0c: Seems to be client asking for user list. data len of 0, so it seems it's just in the
IC. Server responds with 9a 00 and then lists the usernames, each with uname len byte in front
if it worked (check what it does for error (\list asdfasd for instance). datalen includes error
and count bytes in addition to usernames. 

case 09: Seems to be client request for list of rooms. Just ic, no data len. If there's no rooms, it seems a 9a response with 00 error code (and 01 data len) is returned. Imagine it's similar to username request if there are rooms.

case 03: Room join request. Followed by XX for room name len, room name, XX for pword len,
and then pword. If no pword, there'll just be a 00 after room name. Creates room if doesn't exist. Receives a 9a 00 on success.
If incorrect password receives a 9a 01 with fixed message len (no len bytes except the data len)
saying invalid password etc. If already in room and try to join that room, get 9a 01 error (even
if use password. Seems that can't add password if room exists, must be using empty string as
pword if no password given, then requiring empty string for entry). Seems as though a white space doesn't work for a password (get invalid command), but this could be client side yup just
client side.

case 15: Seems to message room. Followed by XX for room name byte len, room name, 
XXXX (msg len), and then msg. Server sends 9a 00 in response if works.
Client seems to send even if not in a room (server sends back 9a 01 you speak to no one). Look into this before implementing. Server sends out message as XX, roomname, XX, uname, XXXX, msg 
Too many messages spark a 9a 02 error (look into this) Seems to be triggered
by 5 messages in less than 5 seconds, even mixing room and dms, and even if outside of rooms
and the error message was sent

case 12: Direct message send from client. Followed by XX for user len, receiver username,
XXXX (msg len), and then message. Seems to receive a 9a 00 from server in response. Server
then forwards the direct message with basically the same thing, XX 04 17 12 etc, but with
the recv uname replaced with the sender uname (obviously fix len fields as well). If user doesnt
exist gets 9a 01 with fixed len error message. Seems to send direct message whether or not in
room, i guess just needs to be on server. (will need to use ptrs to users for data structure?)
Too many messages spark a 9a 02 error (look into this) Seems to be triggered
by 5 messages in less than 5 seconds, even mixing room and dms

case 06: Seems to be the leave instruction. 00 data len. gets a 9a 00 response in return.
Also leaves server if not in room, still gets 9a 00 in that case. \disconnect doesn't seem
to send anything, so it's probably only client side and lets it time out. 




Proposed Technique Outline (in terms of changes to existing code):

REMEMBER, WE'RE DESIGNING THE CLIENTS AND SERVERS, SO WE CAN CHANGE THE MESSAGE FORMATTING ANY WAY WE WANT
AS LONG AS THE TWO COORDINATE

NEW MESSAGE TYPES (make into functions?):
- AES DM Key message (ID: 0x80) (args of function: Key, receiving username) Always sent by the server to clients
    Server encrypts key using user's rsa public key (which will be in the user's rsapub field), and send message to user.
    Separate from room key message, as client can be sent this message at any time, not just after joining a room.

- AES Room Key message (ID: 0x84) (args of function: Key, receiving username) Always sent by the server to clients
    Server encrypts key using user's rsa public key (which will be in the user's rsapub field), and send message to user.


- RSA Public Key message (ID: 0x81) (args of function: Key) Sent by client to server, and server to clients
    Sent by user for server to store in User rsapub field when first joining server. Sent by server to users in the same room as this one or in DM session with. Basically, at any point a user could get this message, and should add the public key to its dict of public keys to usernames for integrity checking.

- DM Request message (ID: 0x82) (args of function: target username)
    Requests server to send back a generated AES key (encrypted with sender's public RSA key) and the target user's
    RSA public key (for integrity checking). This function is called in client send_direct_message function if 
    the client doesn't have an AES key for the target user yet.


- DM Request Response message (ID:0x89)
    Sends back a message: targetuname_len + targetuname + public_key_len + public_key + aes_key
    (AES key is 16 bytes)
- File transmission messages (see end)

More messages from server:
0x9b - Connected. Gives username
0x90 - Username changed confirm. Includes new username
0x91 - Room join confirm. Includes room name
0x93 - Room create confirm. Includes room name
0x92 - Room leave confirm
0x94 - User doesn't exist for DM

3.1: Basic Chat
    
    a)  High-Level: The application will consist of a central server program and the user client     
        programs. Users can create password-protected rooms in which all room members will received room messages, or directly message another user. These messages can also consist of files, at which point the file transfer protocol will be initiated. Logging will be done on the server to track attempts and seek out authentication or message traffic anomalies, but no chat records will be stored. Any failures in key generation or message or file sending/verification will result in error messages being sent to the appropriate parties.
    
    b)  Low-Level:
    
        - Room.__init__: The room class currently stores its password in plain text, so need to change it to being a salted hash. 
        
        - Room.join: Change the equality check to comparisons of the hashed attempt with the stored one.

        - I think there already exists hardcoded error messages spread throughout the program. Might be easier to convert to a single function that takes in an error string, and formats the message correctly.

3.2a: User registration & Room Joining

    a) High-Level: Should we even have user logins? Currently we don't, which I think is fine. Regardless, at registration, each user will locally generate an RSA public/private key pair. The user will store the private key locally, and send the public key to the server (doesn't need to be encrypted, I think). For each chat session via room generation or joining or DMs, a shared AES key will be generated by the server and sent to the relevant clients (or just shared if the key already exists). Whenever a user logs off, their keys are deleted and must be regenerated. As of now we're not adding any integrity checks to the key sendings.

    b) Low-Level:

        - Yeah, let's not have a user login

        - On the client side, the first thing it should do is generate an RSA public/private key pair. Store it locally (was thinking a file, but we can actually just save it to a variable). Send the public key to the server. Make a new message format for both the client and server, and have the client send and the server receive as part of the startup transaction. Add a RSA_public field to the User class, and assign it in User.__init__.

        - Room generation and joining:
        Server: 
            Room.__init__: Create an AES key and send to the user, encrypted via the user's public key (might need a getter to help with getting the various keys). 
            Room.join: Send the room's AES key, same as init, but without generation. Send all the room's users public keys to the new user (using message type 0x81), and the new user's public key to all users in the room.
            
            Both functions use AES room key message to send the AES key, type (0x84)

        Client:
            Room join request: Send the request, and read the returned AES key, decrypt it, and store it locally. Can only be in one room at a time, so can just overwrite existing room key and have a single roomKey AES variable.

            Client needs to also listen for any rsa pub and AES key messages and add them to its dicts.


3.2b: DM Setup

    a) High-level: User DM session messages will also be encrypted by a shared AES key. So we'll need to store an AES key in the client for each DM recepient. User sends request to DM if it doesn't have an AES key for the target user yet. The server generates an AES key, encrypts it using the appropriate public keys, and sends it to both users. It also sends the public keys to both users so they can check integrity.

    b) Low-level:

        - Client will need to have dicts of usernames to public keys and dicts of usernames to DM AES keys (we can technically combine them, or use files instead of variables, but either way works)

        - In client.send_direct_message, need to create protocol:
            1. Check if AES key / public key exists for user
            2. If exists, send messages as described in 3.3
            3. Otherwise, send DM Request message
            4. Receive and decrypt AES key, and store it in the dict. Receive the public key and store it in the dict.
            5. Send message as described in 3.3

        - Server just forwards message to appropriate user if it's a DM message (0x12) type. If it's a DM request message (0x82) type, it generates an AES key. Then it sends it to the sender and target user (message type 0x80), encrypting both with the respective public keys. It also sends each user's public key to the other user (message type 0x81).
    
3.3: Message Transmission

    a) High-Level: For rooms, client sends AES key encrypted message concatenated with hashed message signed with private RSA key to server, server sends it to all in the room, and they decrypt the message using the AES key, and decrypt the hash using the public RSA key, and then compare the hash to a newly computed hash. Essentially slide 22 in lecture 8. For DMs it's the same, but only one recepient.

    b) Low-level: Basically the same as high-level. Implement this protocol in the appropriate server and client functions.

3.4: The hard part: File Transmission Protocol
WE MAY NEED TO INCORPORATE MULTITHREADING HERE AND REMOVE THE DDOS LIMIT IN ORDER TO BE ABLE TO PROCESS THIS MUCH AND STILL ALLOW THE REST TO OCCUR

Just gonna try and specify this chronologically:

Sender Client: 
1. Check file size. If too large (not sure what this'll mean yet, depends on key size), split into chunks.
2. Send a File Transmission Request to server (includes the filename, total number of chunks, overall file size, and
    an encrypted hash of the complete file for integrity checks).

Server:
3. Server forwards request to each recepient in the room (or just the DM, if username is specified, otherwise assume room).

Target Clients:
4. Each client prompts the user whether to accept the file (to send back an Accept File Transmission Request Message)

Server:
5. Server collects all the decisions and builds a list of target users, and creates a bitarray the size of the number 
    of chunks for each user (to track what it has and what it doesn't).

6. Server sends sender client a Start Transmission message (or No Transmission message if there are no target clients)

Sender Client:
7. Sender Client starts sending encrypted file chunks to the server one at a time

Server:
8. Server relays file chunk to all accepting recepients

Target Clients:
9. Upon chunk receipt, client sends back a Chunk Received Message.

Server:
10. If gets a chunk received message, marks off the chunk in the bitmaps. Ors all the bits at the current chunk number to see if they've all received it. If after a certain amount of time, still not all of them have gotten that chunk, check which have a chunk missing, and just remove them from the target clients table and move on.
11. When all have acknowledge the chunk, server sends sender a Next Chunk Message.

Client:
12. Send next chunk if there are, send Transmission Complete message if all have been sent.

Server:
13. Relay this message to all target recepients, and delete table

Target clients:
14. Reassemble chunks, decrypt, and comput the hash to check file integrity. Remove the RSA signature on the hash using the sender's public key and compare.



