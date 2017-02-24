import webapp2, jinja2, os, re
from google.appengine.ext import db
from models import Post, User
import hashutils

# this is dev_blogz
# see walkthrough video https://youtu.be/KtPNiBUlqA0

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class BlogHandler(webapp2.RequestHandler):
    """ Utility class for gathering various useful methods that are used by most request handlers """

    def get_posts(self, limit, offset):
        """ Get all posts ordered by creation date (descending) """
        query = Post.all().order('-created')
        return query.fetch(limit=limit, offset=offset)

    def get_posts_by_user(self, user, limit, offset):
        """
            Get all posts by a specific user, ordered by creation date (descending).
            The user parameter will be a User object.
        """

        # TODO - filter the query so that only posts by the given user
        # http://blogz-demo.appspot.com/blog/joel
        # called when click link on main blog page
        query = Post.all().order('-created').filter("author", user)
        return query.fetch(limit=limit, offset=offset)
        #return None

    def get_user_by_name(self, username):
        """ Get a user object from the db, based on their username """
        # called from line 275
        user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username)
        if user:
            print("line 44 user already exists == ", username)
            return user.get()

    def login_user(self, user):
        """ Login a user specified by a User object user """
        user_id = user.key().id()
        print("line 42 login_user() user_id == ", user_id)
        # store the user_id in a cookie
        # called from line 243 and 290
        self.set_secure_cookie('user_id', str(user_id))

    def logout_user(self):
        """ Logout a user specified by a User object user """
        # class LogoutHandler(BlogHandler): at line 296
        print("line 50 logout_user = ", self)
        self.set_secure_cookie('user_id', '')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = hashutils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def initialize(self, *a, **kw):
        """
            A filter to restrict access to certain pages when not logged in.
            If the request path is in the global auth_paths list, then the user
            must be signed in to access the path/resource.
            auth_paths = [ '/blog/newpost' ]
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))
        if self.user:
            print("line 74 initialize uid, User.get_by_id(int(uid)) == ", self.user, uid, User.get_by_id(int(uid)))

        if not self.user and self.request.path in auth_paths:
            # auth_paths on line 314
            self.redirect('/login')

class IndexHandler(BlogHandler):

    def get(self):
        """ List all blog users on home page """
        users = User.all()
        user = self.user
        if user:
            print("line 93 users, username == ", users, user.username)
        t = jinja_env.get_template("index.html")
        response = t.render(users = users, user = self.user)
        self.response.write(response)

class BlogIndexHandler(BlogHandler):

    # number of blog posts per page to display
    page_size = 5

    def get(self, username=""):
        """ """
        print("line 106 self, username == ", self.user, username)
        users = User.all()
        # If request is for a specific page, set page number and offset accordingly
        page = self.request.get("page")
        offset = 0
        page = page and int(page)
        if page:
            offset = (int(page) - 1) * self.page_size
        else:
            page = 1

        # Fetch posts for all users, or a specific user, depending on request parameters
        if username:
            user = self.get_user_by_name(username)
            print("line 112 username == ",username)
            posts = self.get_posts_by_user(user, self.page_size, offset)
            print("line 114 posts == ", posts)
            print("line 115 username, user, posts == ",username, user, posts)
            for p in posts:
                print("line 117 p == ", p)
            print("line 118 username, user, posts == ",username, user, posts)
        else:
            posts = self.get_posts(self.page_size, offset)
            print("line 121 posts == ", posts)

        # determine next/prev page numbers for navigation links
        if page > 1:
            prev_page = page - 1
            print("prev_page == ", prev_page)
        else:
            prev_page = None

        if len(posts) == self.page_size and Post.all().count() > offset+self.page_size:
        # TypeError: object of type 'NoneType' has no len() for text username
        # routes to ViewPostHandler if username is numeric
            print("line 133 len(posts) == ", len(posts))
            next_page = page + 1
            print("line 135 next_page == ", next_page)
        else:
            next_page = None

        # render the page
        user = self.user
        print("line 142 user == ", user, username)
        print("line 143 render blog.html == ", posts)
        print("line 144 render blog.html == ", page, self.page_size, prev_page, next_page)
        print("line 145 len(posts) == ", len(posts))
        for i in range(len(posts)):
            print("line 147 posts[" + str(i) + "].author.username == ", posts[i].author.username)
        t = jinja_env.get_template("blog.html")
        response = t.render(
                    posts=posts,
                    page=page,
                    page_size=self.page_size,
                    prev_page=prev_page,
                    next_page=next_page,
                    username=username,
                    user = user,
                    users = users)
        self.response.out.write(response)

class NewPostHandler(BlogHandler):

    def render_form(self, title="", body="", error=""):
        """ Render the new post form with or without an error, based on parameters """
        user = self.user
        t = jinja_env.get_template("newpost.html")
        response = t.render(title=title, body=body, error=error, user = user)
        self.response.out.write(response)

    def get(self):
        self.render_form()

    def post(self):
        """ Create a new blog post if possible. Otherwise, return with an error message """
        title = self.request.get("title")
        body = self.request.get("body")
        print("title, body == ", title, body)

        if title and body:

            # create a new Post object and store it in the database
            post = Post(
                title=title,
                body=body,
                author=self.user
                )
            post.put()

            # get the id of the new post, so we can render the post's page (via the permalink)
            id = post.key().id()
            print("id == ",id)
            self.redirect("/blog/%s" % id)
        else:
            error = "we need both a title and a body!"
            self.render_form(title, body, error)

class ViewPostHandler(BlogHandler):

    def get(self, id):
        """ Render a page with post determined by the id (via the URL/permalink) """

        post = Post.get_by_id(int(id))  # same as studio6 Movie.get_by_id(int(movie_id))
        if post:
            t = jinja_env.get_template("post.html")
            response = t.render(post=post, user=self.user)
        else:
            error = ("there is no post with id %s" % id)
            t = jinja_env.get_template("404.html") # says nothing here!
            response = t.render(error=error)
        self.response.out.write(response)

class SignupHandler(BlogHandler):

    def validate_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            return username
        else:
            return ""

    def validate_password(self, password):
        PWD_RE = re.compile(r"^.{3,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        if password == verify:
            return verify

    def validate_email(self, email):

        # allow empty email field
        if not email:
            return ""

        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if EMAIL_RE.match(email):
            return email

    def get(self):
        user = ""
        t = jinja_env.get_template("signup.html")
        response = t.render(errors={}, user = user)
        self.response.out.write(response)

    def post(self):
        """
            Validate submitted data, creating a new user if all fields are valid.
            If data doesn't validate, render the form again with an error.

            This code is essentially identical to the solution to the Signup portion
            of the Formation assignment. The main modification is that we are now
            able to create a new user object and store it when we have valid data.
        """

        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")
        submitted_email = self.request.get("email")

        username = self.validate_username(submitted_username)
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)
        email = self.validate_email(submitted_email)

        errors = {}
        existing_user = self.get_user_by_name(username)
        # get_user_by_name(username) method is at line 28 in class BlogHandler():
        print("line 277 existing_user = self.get_user_by_name(username) == ", username)
        has_error = False

        if existing_user:
            errors['username_error'] = "A user with that username already exists"
            has_error = True
        elif (username and password and verify and (email is not None) ):

            # create new user object and store it in the database
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, pw_hash=pw_hash)
            user.put()
            print("username, pw_hash == ", user.username, user.pw_hash)

            # login our new user
            # login_user(self, user) method is at line 34 in class BlogHandler():
            self.login_user(user)
        else:
            has_error = True

            # validation methods begin at line 170
            if not username:
                errors['username_error'] = "That's not a valid username"

            if not password:
                errors['password_error'] = "That's not a valid password"

            if not verify:
                errors['verify_error'] = "Passwords don't match"

            if email is None:
                errors['email_error'] = "That's not a valid email"

        if has_error:
            t = jinja_env.get_template("signup.html")
            response = t.render(username=username, email=email, errors=errors)
            self.response.out.write(response)
        else:
            self.redirect('/blog/newpost')

class LoginHandler(BlogHandler):

    # TODO - The login code here is mostly set up for you, but there isn't a template to log in

    def render_login_form(self, error=""):
        """ Render the login form with or without an error, based on parameters """
        t = jinja_env.get_template("login.html")  # login.html template from demo
        user = ""
        response = t.render(error=error, user = user)
        self.response.out.write(response)

    def get(self):
        self.render_login_form()

    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        # get the user from the database
        user = self.get_user_by_name(submitted_username)

        if not user:
            self.render_login_form(error="Invalid username")
        elif hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.login_user(user)
            self.redirect('/blog/newpost')
        else:
            self.render_login_form(error="Invalid password")

class LogoutHandler(BlogHandler):

    def get(self):
        self.logout_user()  # logout_user() on line 40
        self.redirect('/blog')

class Stats(BlogHandler):

    def get(self):
#        user = self.user
#        post = Post.all()
        users = User.all()
        posts = Post.all()

        for usr in users:
            usrkey = int(usr.key().id())
            print("line 365 user.username, usrkey == ", usr.username, usrkey)


# note about dict syntax: {defined} (list comprehension) and [n]
# count = modelname.all(keys_only=True).count()
        t = jinja_env.get_template("stats.html")
        response = t.render(user=self.user, users=users, posts=posts)
        self.response.out.write(response)


app = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/blog', BlogIndexHandler),
    ('/blog/newpost', NewPostHandler),
    webapp2.Route('/blog/<id:\d+>', ViewPostHandler),
#    webapp2.Route('/blog/<username:^[a-zA-Z0-9_-]{3,20}>', BlogIndexHandler),
    webapp2.Route('/blog/user/<username:[a-zA-Z0-9_-]{3,20}>', BlogIndexHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/stats', Stats)
], debug=True)

# A list of paths that a user must be logged in to access
# def initialize(self, *a, **kw): on line 55 and used on line 65
auth_paths = [
    '/blog/newpost'
]
