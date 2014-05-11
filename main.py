import os
import webapp2
import jinja2
from google.appengine.ext import db
import user
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


class Article(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

#Base Class to the handlers
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    #Render the html using the template (Jinja2)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#NewPost Handler
class NewPost(Handler):
	def render_front(self, error = "", subject = "", content = ""):
		self.render("newpost.html", error = error, subject = subject, content = content)
	def get(self):
		self.render_front()
	#Validate the post, save in the db and redirect to it's permalink
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		if subject and content:
			a = Article(subject = subject, content = content)
			a_key = a.put()

			self.redirect("/%d" %a_key.id())
		else:
			error = "we need both a subject and some content!"
			self.render_front(error, subject, content)
#Load and Render a post with permalink
class PostHandler(Handler):
	def render_front(self, id):
		article = Article.get_by_id(int(id))
		self.render("main.html",  articles = [article])
	def get(self, id):
			self.render_front(id)

#Load and render all posts
class MainPage(Handler):
	def render_front(self):
		articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC")
		self.render("main.html",  articles = articles)

	def get(self):
		self.render_front()

class SignUpHandler(Handler):
	def render_front(self, username = "", password = "", verify= "", email = "", vUsername = "", vPassword = "", vEmail = "", vVerify = True):
		user_error = ""
		password_error = ""
		email_error = ""
		verify_error = ""
		if vUsername == None:
			user_error = "That's not a valid username."
		elif vUsername == 0:
			user_error = "That user already exists."
		if vPassword == None:
			password_error = "That wasn't a valid password."
		elif not vVerify:
			verify_error = "Your passwords didn't match."
		if  vEmail == None:
			if email != "":
				email_error = "That's not a valid email."
		self.render("signup.html", username = username, password = password, username_error = user_error, verify = verify, email = email, password_error = password_error,
			email_error = email_error, verify_error = verify_error)

	def validate_user(self, username):
		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		return USER_RE.match(username)
	def validate_email(self, email):
		USER_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
		return USER_RE.match(email)
	def validate_password(self, password):
		USER_RE = re.compile(r"^.{3,20}$")
		return USER_RE.match(password)

	def get(self):
		self.render_front()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		vUsername = self.validate_user(username)
		vPassword = self.validate_password(password)
		vEmail = self.validate_email(email)
		vVerify = password == verify

		if(vUsername and vPassword and vVerify):
			validate = user.newUser(username, password)
			if(validate == None):
				vUsername = 0
				self.render_front(username, password, verify, email, vUsername, vPassword, vEmail, vVerify)
			else:
				self.response.headers.add_header('Set-Cookie', "user_id=%s; Path=/" % validate)
				self.redirect("/welcome")
		else:
			self.render_front(username, password, verify, email, vUsername, vPassword, vEmail, vVerify)

class WelcomeHandler(Handler):
	def render_front(self):
		cookie = self.request.cookies.get('user_id')
		username = user.validateUserHash(cookie)
		if(username):
			self.render("welcome.html", user = username)
		else:
			self.redirect("/signup")
	def get(self):
		self.render_front()

class LoginHandler(Handler):
	def render_front(self, username = "", error=""):
		self.render("login.html", user = username, error = error)
		
	def get(self):
		self.render_front()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		validate = user.validate_password(username, password)
		if validate == None:
			self.render_front(username, "Invalid username!")
		elif validate == False:
			self.render_front(username, "Invalid password!")
		else:
			self.response.headers.add_header('Set-Cookie', "user_id=%s; Path=/" % validate)
			self.redirect("/welcome")
			
class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
		self.redirect("/signup")
		

#Handlers
#The last handler uses regex to find the post id in the url.
app = webapp2.WSGIApplication([('/', MainPage), ('/signup', SignUpHandler), ('/logout', LogoutHandler)
	,('/welcome', WelcomeHandler)  , ('/login', LoginHandler),('/newpost', NewPost), ('/blog/newpost', NewPost) ,(r'/(\d+)', PostHandler)], debug=True)