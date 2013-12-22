import hashlib
import random
import string

SECRET = "difhbTDJFBKRSTWJRJSEWe439085029384SFJSEFJSE"


# returns hash of the password
def create_pwd_hash(password):
        return hmac.new(SECRET, password).hexdigest()


# returns True iff the hash of given password is equal to h
def validate_pwd(password, h):
        return hmac.new(SECRET, password).hexdigest() == h


def make_salt():
    return ''.join(random.choice(string.letters) for _ in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)