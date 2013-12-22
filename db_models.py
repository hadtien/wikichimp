__author__ = 'yura'

from google.appengine.ext import db


class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)


class Page(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    #created = db.DateProperty(auto_now_add=True)
