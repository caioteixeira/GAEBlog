from hashlib import sha256
from google.appengine.ext import db

keyword = "batata"

class User(db.Model):
	user = db.StringProperty(required = True)
	password = db.StringProperty(required = True)

def newUser(username, password):
	query = db.GqlQuery("SELECT * FROM User WHERE user = '%s'"%username)
	if query.get() != None:
		return None
	else:
		password = sha256(password+keyword).hexdigest()
		user = User(user = username, password = password)
		user = user.put()
		user_id = user.id()
		#TODO: Return cookie
		return createUserHash(user_id)


def validate_password(username, password):
	password = sha256(password+keyword).hexdigest()
	query = User.all().filter("user =", username)
	user = query.get()
	if user == None:
		return None
	elif user.password != password:
		return False
	else:
		return createUserHash(user.key().id())

def createUserHash(user_id):
	return str(user_id)+'|' + sha256(str(user_id) + keyword).hexdigest()

def validateUserHash(h):
	id = h.split('|')[0]
	if  h != createUserHash(id):
		return False
	user = User.get_by_id(int(id))
	
	return user.user
