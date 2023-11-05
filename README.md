# Chat Replica
## Assignment 3
See the assignment specification.

The binaries needed for this project can be found in [materials](https://gitlab.cs.umd.edu/cmsc417-s23/all/materials/-/tree/main/a3/). See Piazza for the IP:Port for the class chat server.


You may reuse any code from previous assignments.

## DUE
**April 8, 11:59:59 PM ET**

## Piazza
Please tag any questions pertaining to this assignment with `a3`.


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


