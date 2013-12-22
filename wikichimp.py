import os
import webapp2
import re
import jinja2

import utils
from db_models import User, Page

template_dir = os.path.join(os.path.dirname(__file__), './templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class SignupPage(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        uname_error, pwd_error, pwd_error_match, email_error, uname_exists = '', '', '', '', ''

        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        pwd_re = re.compile(r"^.{3,20}$")
        email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        if not user_re.match(username):
            uname_error = "That's not a valid username."
        if not pwd_re.match(password):
            pwd_error = "That wasn't a valid password."
        elif password != verify:
            pwd_error_match = "Your passwords didn't match."
        if email and not email_re.match(email):  # email optional
            email_error = "That's not a valid email."

        user = User(username=username, password_hash=utils.make_pw_hash(username, password))

        q = User.all()
        q.filter("username =", username)

        if q.count() > 0:
            uname_exists = "Username exists"
        if uname_error or pwd_error or pwd_error_match or email_error or uname_exists:
            self.render("signup.html", username_error=uname_error, password_error=pwd_error,
                        verify_error=pwd_error_match, email_error=email_error, usernam=username,
                        email=email, username_exists=uname_exists)
        else:
            user.put()
            self.response.headers.add_header('Set-Cookie', 'uname=%s;Path=/' % str(username))
            self.redirect("/")


class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'uname=;Path=/')
        self.redirect("/")


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        q = User.all()
        q.filter("username =", username)
        if q.count() == 0:  # user doesn't exist
            self.render("login.html", invalid_login="User doesn\'t exist")
            return
        user = q.get()
        if not utils.valid_pw(username, password, user.password_hash):
            self.render("login.html", invalid_login="Wrong password")
            return
        else:
            self.response.headers.add_header('Set-Cookie', 'uname=%s;Path=/' % str(username))
            self.redirect("/")


class EditPage(Handler):
    pass


class WikiPage(Handler):
    pass


class MainPage(Handler):
    def get(self):
        uname = self.request.cookies.get("uname")
        if uname:
            self.render("main.html", username=uname, logged_in=True)
        else:
            self.render("main.html", logged_in=False)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([('/', MainPage),
                                       ('/login', LoginPage),
                                       ('/logout', LogoutPage),
                                       ('/signup', SignupPage),
                                       (PAGE_RE, WikiPage),
                                       ('/_edit' + PAGE_RE, EditPage)],
                                      debug=True)