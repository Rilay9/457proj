# Represents a Room. Has a list of users in the room, a name,
# and a password.

from user import User

class Room:

    all_rooms = {}

    # Creates the room. The user who creates it is always added.
    def __init__(self, user:User, room_name:str, pword:str) -> None:
        self.room_users = {user.name: user}
        self.name = room_name
        self.password = pword
        user.room = self.name
        Room.all_rooms[room_name] = self # Caller checks if name already exists

    # Join the room. Returns true if password was correct and user
    # was added, and false otherwise
    def join(self, user:User, pword:str) -> bool:
        
        if pword == self.password:

            # Add user to room users
            self.room_users[user.name] = user

            # Removes user from old room
            if user.room is not None:
                old_room = Room.all_rooms[user.room]
                old_room.remove(user)
            
            # Updates user's room
            user.join_room(self.name)
            return True
        else:
            return False
    
    # Returns sorted list of user names in room
    def list_users(self):
        return sorted([username for username in self.room_users.keys()])

    # Returns sorted list of all room names
    @staticmethod
    def list_rooms():
        return sorted([room_name for room_name in Room.all_rooms.keys()])

    # Removes user from room (Caller checks if not in room). If 
    # user was the only one in the room, deletes the room
    def remove(self, user:User) -> None:
        
        del self.room_users[user.name]
        user.leave()

        if len(self.room_users) == 0:
            del self.all_rooms[self.name]


