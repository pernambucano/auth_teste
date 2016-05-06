#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import hmac
import hashlib
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


SECRET = "secret"


def make_salt():
    return "".join(random.choice(string.letters) for i in range(5))


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_pw_hash(username, pw, salt = None):
    if not salt:
        salt = make_salt()
    return "%s,%s" % (hashlib.sha256(username+pw+salt).hexdigest(), salt)


def validate_pw_hash(username, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(username, pw, salt)


def make_secure_hash(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_hash(val):
        return val


class Handler(webapp2.RequestHandler):

    def write(self, *a, **k):
        self.response.out.write(*a, **k)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Account(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    verify_password = db.StringProperty()
    email = db.EmailProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class SignUpHandler(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        # get info from form request
        username = self.request.get('username')
        password = self.request.get('password')
        verify_password = self.request.get('verify_password')
        email = self.request.get('email')

        # is the information right?
        if username and password and (password == verify_password):
            secure_password = make_pw_hash(username, password)
            user_id = 0
            if not Account.get_by_key_name(username):
                if email:
                    account = Account(username=username, password=secure_password,
                                      email=email, id=username)
                else:
                    account = Account(username=username, password=secure_password,
                                      id=username)
                account.put()
                user_id = account.key().id()

            else:
                user_id = Account.get_by_key_name(username).key().id()

            print(user_id)

            cookie_user_id = make_secure_hash(str(user_id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/'
                                             % cookie_user_id)
            self.redirect("/welcome")
        else:
            # return error
            error = "we need all the information"
            self.render("signup.html", error=error)


class WelcomeHandler(Handler):

    def get(self):

        user_id = self.request.cookies.get("user_id")
        if user_id:
            cookie_user_id = check_secure_val(user_id)
            if cookie_user_id:
                user_id = int(cookie_user_id)
            else:
                user_id = 0
            user = Account.get_by_id(user_id)
            print("user id: %s" % user.username)
            self.render("welcome.html", user_name=user.username)
        else:
            self.render("welcome.html")


app = webapp2.WSGIApplication([
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
