
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

3.1: Basic Chat
    
    a)  High-Level: The application will consist of a central server program and the user client     
        programs. Users can create password-protected rooms in which all room members will received room messages, or directly message another user. These messages can also consist of files, at which point the file transfer protocol will be initiated. Logging will be done on the server to track attempts and seek out authentication or message traffic anomalies, but no chat records will be stored. Any failures in key generation or message or file sending/verification will result in error messages being sent to the appropriate parties.
    
    b)  Low-Level:
    
        - Room.__init__: The room class currently stores its password in plain text, so need to change it to being a salted hash. 
        
        - Room.join: Change the equality check to comparisons of the hashed attempt with the stored one.

        - I think there already exists hardcoded error messages spread throughout the program. Might be easier to convert to a single function that takes in an error string, and formats the message correctly.

3.3: User Authentication & Key Generation

    a) High-Level: Should we even have user logins? Currently we don't. It could just be anonymous, with each client connection essentially treated as a new user. Regardless, at registration, each user will locally generate an RSA public/private key pair. The user will store the private key locally, and send the public key to the server (doesn't need to be encrypted, right?). For each chat session, whether via room generation or direct message, a shared AES key will be generated. Whenever a user logs off, their keys are deleted and must be regenerated. Not ideal, but as of now we're not adding any integrity checks to the key sendings.

    b) Low-Level:

        - Yeah, let's not have a user login

        - On the client side, the first thing it should do is generate an RSA public/private key pair. Store it locally in a file (don't think we need to worry about encrypting it). Send the public key to the server. Make a new message format for both the client and server, and have the client send and the server receive as part of the startup transaction. Add a RSA_public field to the User class, and assign it in User.__init__.

        - Room generation and joining:
        Server: 
            Room.__init__: Create an AES key and send to the user, encrypted via the user's public key (might need a getter to help with getting the various keys).
            Room.join: Send the room's AES key, same as init, but without generation.

        Client:
            Room join request: Send the request, and read the AES key, decrypt it, and store it locally.


