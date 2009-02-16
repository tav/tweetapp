"""TweetApp Framework."""

# Released into the Public Domain by tav@espians.com

import logging
import os
import sys

from BaseHTTPServer import BaseHTTPRequestHandler
from cgi import parse_qsl as parse_query_string
from Cookie import SimpleCookie
from datetime import datetime, timedelta
from hashlib import sha1
from hmac import new as hmac
from os.path import dirname, join as join_path, getmtime
from pprint import pprint
from re import compile as compile_regex
from random import getrandbits
from StringIO import StringIO
from time import time
from traceback import format_exception
from urllib import urlencode, quote as urlquote, unquote as urlunquote
from uuid import uuid4
from wsgiref.headers import Headers

# ------------------------------------------------------------------------------
# extend sys.path to include the ``third_party`` lib direktory
# ------------------------------------------------------------------------------

APP_DIRECTORY = dirname(__file__)

sys.path.insert(0, join_path(APP_DIRECTORY, 'third_party'))

# ------------------------------------------------------------------------------
# import other libraries
# ------------------------------------------------------------------------------

from demjson import decode as decode_json
from format_traceback import HTMLExceptionFormatter
from genshi.core import Markup
from genshi.template import MarkupTemplate, TextTemplate, TemplateLoader
from webob import Request as WebObRequest

from google.appengine.api.urlfetch import fetch as urlfetch, GET, POST
from google.appengine.ext import db

from source.config import *

# ------------------------------------------------------------------------------
# exseptions
# ------------------------------------------------------------------------------

class Error(Exception):
    """Base TweetApp Exception."""

class Redirect(Error):
    """
    Redirection Error.

    This is used to handle both internal and HTTP redirects.

    """

    def __init__(self, uri, method=None, permanent=False):
        self.uri = uri
        self.method = method
        self.permanent = permanent

class UnAuth(Error):
    """Unauthorised."""

class NotFound(Error):
    """404."""

class ReturnValue(Error):
    """Service return value."""

def format_traceback(type, value, traceback, limit=200):
    return HTMLExceptionFormatter(limit).formatException(type, value, traceback)

# ------------------------------------------------------------------------------
# i/o helpers
# ------------------------------------------------------------------------------

class DevNull:
    """Provide a file-like interface emulating /dev/null."""

    def __call__(self, *args, **kwargs):
        pass

    def flush(self):
        pass

    def log(self, *args, **kwargs):
        pass

    def write(self, input):
        pass

DEVNULL = DevNull()

# ------------------------------------------------------------------------------
# wsgi
# ------------------------------------------------------------------------------

SSL_ENABLED_FLAGS = frozenset(['yes', 'on', '1'])

def run_wsgi_app(application, ssl_enabled_flags=SSL_ENABLED_FLAGS):
    """Run a WSGI ``application`` inside a CGI environment."""

    environ = dict(os.environ)

    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.input'] = sys.stdin
    environ['wsgi.multiprocess'] = False
    environ['wsgi.multithread'] = False
    environ['wsgi.run_once'] = True
    environ['wsgi.version'] = (1, 0)

    if environ.get('HTTPS') in ssl_enabled_flags:
        environ['wsgi.url_scheme'] = 'https'
    else:
        environ['wsgi.url_scheme'] = 'http'

    sys._boot_stdout = sys.stdout
    sys.stdout = DEVNULL
    write = sys._boot_stdout.write

    try:
        result = application(environ, start_response)
        if result is not None:
            for data in result:
                write(data)
    finally:
        sys.stdout = sys._boot_stdout

def start_response(status, response_headers, exc_info=None):
    """Initialise a WSGI response with the given status and headers."""

    if exc_info:
        try:
            raise exc_info[0], exc_info[1], exc_info[2]
        finally:
            exc_info = None # bye-bye sirkular ref

    write = sys._boot_stdout.write
    write("Status: %s\r\n" % status)

    for name, val in response_headers:
        write("%s: %s\r\n" % (name, val))

    write('\r\n')

    return write

# ------------------------------------------------------------------------------
# general http util
# ------------------------------------------------------------------------------

def get_http_datetime(timestamp=None):
    """Return an HTTP header date/time string."""

    if timestamp:
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromtimestamp(timestamp)
    else:
        timestamp = datetime.utcnow()

    return timestamp.strftime('%a, %d %B %Y %H:%M:%S GMT') # %m

# ------------------------------------------------------------------------------
# http response
# ------------------------------------------------------------------------------

HTTP_STATUS_MESSAGES = BaseHTTPRequestHandler.responses

class Response(object):
    """HTTP Response."""

    def __init__(self):
        self.cookies = {}
        self.status = []
        self.stream = StringIO()
        self.write = self.stream.write
        self.raw_headers = []
        self.headers = Headers(self.raw_headers)
        self.set_header = self.headers.__setitem__

    def set_response_status(self, code, message=None):
        if not message:
            if not HTTP_STATUS_MESSAGES.has_key(code):
                raise Error('Invalid HTTP status code: %d' % code)
            message = HTTP_STATUS_MESSAGES[code][0]
        self.status[:] = (code, message)

    def clear_response(self):
        self.stream.seek(0)
        self.stream.truncate(0)

    def set_status_and_clear_response(self, code):
        self.set_response_status(code)
        self.clear_response()

    def set_cookie(self, name, value, **kwargs):
        cookie = self.cookies.setdefault(name, {})
        cookie['value'] = value
        kwargs.setdefault('path', '/')
        for name, value in kwargs.iteritems():
            if value:
                cookie[name.lower()] = value

    def append_to_cookie(self, name, value):
        cookie = self.cookies.setdefault(name, {})
        if 'value' in cookie:
            cookie['value'] = '%s:%s' % (cookie['value'], value)
        else:
            cookie['value'] = value

    def expire_cookie(self, name, **kwargs):
        if name in self.cookies:
            del self.cookies[name]
        kwargs.setdefault('path', '/')
        kwargs.update({'max_age': 0, 'expires': "Fri, 31-Dec-99 23:59:59 GMT"})
        self.set_cookie(name, 'deleted', **kwargs) # @/@ 'deleted' or just '' ?

    def set_to_not_cache_response(self):
        headers = self.headers
        headers['Expires'] = "Fri, 31 December 1999 23:59:59 GMT"
        headers['Last-Modified'] = get_http_datetime()
        headers['Cache-Control'] = "no-cache, must-revalidate" # HTTP/1.1
        headers['Pragma'] =  "no-cache"                        # HTTP/1.0

# ------------------------------------------------------------------------------
# kookie support
# ------------------------------------------------------------------------------

COOKIE_KEY_NAMES = frozenset([
    'domain', 'expires', 'httponly', 'max-age', 'path', 'secure', 'version'
    ])

def get_cookie_headers_to_write(cookies, valid_keys=COOKIE_KEY_NAMES):
    """Return HTTP response headers for the given ``cookies``."""

    output = SimpleCookie()

    for name, values in cookies.iteritems():

        name = str(name)
        output[name] = values.pop('value')
        cur = output[name]

        for key, value in values.items():
            if key == 'max_age':
                key = 'max-age'
            # elif key == 'comment':
            #     # encode rather than throw an exception
            #     v = quote(v.encode('utf-8'), safe="/?:@&+")
            if key not in valid_keys:
                continue
            cur[key] = value

    return str(output)

# ------------------------------------------------------------------------------
# kore wsgi applikation
# ------------------------------------------------------------------------------

HTTP_HANDLERS = {}
register_http_handler = HTTP_HANDLERS.__setitem__

def Application(environ, start_response, handlers=HTTP_HANDLERS):
    """Core WSGI Application."""

    env_copy = dict(environ)
    response = Response()

    http_method = environ['REQUEST_METHOD']

    try:

        if http_method in handlers:
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            response.headers['Cache-Control'] = 'no-cache'
            response.set_response_status(200)
            handlers[http_method](environ, response)
        else:
            response.set_status_and_clear_response(501)

    except Redirect, redirect:

        # internal redirekt
        if redirect.method:
            env_copy['REQUEST_METHOD'] = redirect.method
            if '?' in redirect.uri:
                (env_copy['PATH_INFO'],
                 env_copy['QUERY_STRING']) = redirect.uri.split('?', 1)
            else:
                env_copy['PATH_INFO'] = redirect.uri
                env_copy['QUERY_STRING'] = ''
            return Application(
                env_copy, start_response, handlers, response_factory
                )

        # external redirekt
        if redirect.permanent:
            response.set_response_status(301)
        else:
            response.set_response_status(302)

        response.headers['Location'] = str(
            urljoin('', redirect.uri)
            )
        response.clear_response()

    except Exception, exception:

        response.set_status_and_clear_response(500)
        lines = ''.join(format_exception(*sys.exc_info()))
        logging.error(lines)

        if DEBUG_MODE:
            response.headers['Content-Type'] = 'text/plain'
            response.write(lines)

        return

    content = response.stream.getvalue()

    if isinstance(content, unicode):
        content = content.encode('utf-8')
    elif response.headers.get('Content-Type', '').endswith('; charset=utf-8'):
        try:
            content.decode('utf-8')
        except UnicodeError, error:
            logging.warning('Response written is not UTF-8: %s', error)

    response.headers['Content-Length'] = str(len(content))

    raw_headers = response.raw_headers + [
        ('Set-Cookie', ck.split(' ', 1)[-1])
        for ck in get_cookie_headers_to_write(response.cookies).split('\r\n')
        ]

    write = start_response('%d %s' % tuple(response.status), raw_headers)

    if http_method != 'HEAD':
        write(content)

    response.stream.close()

    return [''] # @/@ why do we have this instead of None ??

# ------------------------------------------------------------------------------
# http request objekt
# ------------------------------------------------------------------------------

VALID_CHARSETS = frozenset(['utf-8'])
find_charset = compile_regex(r'(?i);\s*charset=([^;]*)').search

class RequestAPI(object):
    """HTTP Request."""

    def __init__(
        self, environ, response, parse_query_string=parse_query_string,
        find_charset=find_charset, urlunquote=urlunquote
        ):

        self.service_name = ''
        self.request_method = environ['REQUEST_METHOD']

        self.environ = environ
        self.response = response

        self.append_to_cookie = response.append_to_cookie
        self.expire_cookie = response.expire_cookie
        self.set_cookie = response.set_cookie
        self.clear_response = response.clear_response
        self.Redirect = Redirect
        self.response_headers = response.headers
        self.set_response_header = response.set_header
        self.set_response_status = response.set_response_status
        self.set_status_and_clear_response = response.set_status_and_clear_response
        self.set_to_not_cache_response = response.set_to_not_cache_response

        path = environ['PATH_INFO']
        query = environ['QUERY_STRING']
        scheme = environ['wsgi.url_scheme']
        port = environ['SERVER_PORT']

        self.site_uri = (
            scheme + '://' + environ['SERVER_NAME'] + ((
                (scheme == 'http' and port != '80') or 
                (scheme == 'https' and port != '443')
                ) and ':%s' % port or '')
            )

        self.uri = self.site_uri + path
        self.uri_with_qs = self.uri + (query and '?' or '') + query

        self.request_charset = 'utf-8'

        request_content_type = environ.get('CONTENT-TYPE', '')

        if request_content_type:
            match = find_charset(request_content_type)
            if match:
                match = match.group(1).lower()
                if match in VALID_CHARSETS:
                    self.request_charset = match


        self.request_args = tuple(
            unicode(arg, self.request_charset, 'strict')
            for arg in path.split('/') if arg
            )

        self.request_flags = flags = set()
        self.request_kwargs = kwargs = {}

        _val = None

        for part in [
            sub_part
            for part in query.lstrip('?').split('&')
            for sub_part in part.split(';')
            ]:
            if not part:
                continue
            part = part.split('=', 1)
            if len(part) == 1:
                flags.add(urlunquote(part[0].replace('+', ' ')))
                continue
            key = urlunquote(part[0].replace('+', ' '))
            value = part[1]
            if value:
                value = unicode(
                    urlunquote(value.replace('+', ' ')),
                    request_charset, 'strict'
                    )
            else:
                value = None
            if key in kwargs:
                _val = kwargs[key]
                if isinstance(_val, list):
                    _val.append(value)
                else:
                    kwargs[key] = [_val, value]
                continue
            kwargs[key] = value

        self.cookies = cookies = {}
        cookie_data = environ.get('HTTP_COOKIE', '')

        if cookie_data:
            _parsed = SimpleCookie()
            _parsed.load(_data)
            for name in _parsed:
                cookies[name] = _parsed[name].value

    def compute_site_uri(self, *args, **kwargs):

        request_charset = self.request_charset

        out = self.site_uri + '/' + '/'.join(
            arg.encode(request_charset) for arg in args
            )

        if kwargs:
            out += '?'
            _set = 0
            _l = ''
            for key, value in kwargs.items():
                key = urlquote(key).replace(' ', '+')
                if value is None:
                    value = ''
                if isinstance(value, list):
                    for val in value:
                        if _set: _l = '&'
                        out += '%s%s=%s' % (
                            _l, key,
                            urlquote(val.encode(request_charset)).replace(' ', '+')
                            )
                        _set = 1
                else:
                    if _set: _l = '&'
                    out += '%s%s=%s' % (
                        _l, key, quote(value.encode(request_charset)).replace(' ', '+')
                        )
                    _set = 1

        return out

    def get_cookie(self, name, default=''):
        return self.cookies.get(name, default)

    def get_current_user(self): # @/@
        return player

    def get_current_user_id(self): # @/@
        return player_uuid

    def get_request_object(self):
        return WebObRequest(self.environ)

    def pretty_print(self, object):
        stream = StringIO()
        pprint(object, stream)
        self.response.write(stream.getvalue())

    def out(self, arg): # *args
        if isinstance(arg, str):
            self.response.write(arg)
        elif isinstance(arg, unicode):
            self.response.write(arg.encode('utf-8'))
        else:
            self.response.write(str(arg))

# ------------------------------------------------------------------------------
# servise registries and builtins
# ------------------------------------------------------------------------------

SERVICE_REGISTRY = {}
SLOT_REGISTRY = {}
RENDERER_REGISTRY = {}
TITLE_REGISTRY = {}

BUILTINS = {
    'DEBUG_MODE': DEBUG_MODE,
    'STATIC': SITE_STATIC_URL,
    'Markup': Markup,
    'content_slot': '',
    'urlencode': urlencode,
    'urlquote': urlquote,
    }

# ------------------------------------------------------------------------------
# http request handlers
# ------------------------------------------------------------------------------

SUPPORTED_HTTP_METHODS = ('OPTIONS', 'GET', 'HEAD', 'POST', 'DELETE')

def handle_http_request(environ, response, builtins=BUILTINS):
    """Handle generic HTTP requests."""

    api = RequestAPI(environ, response)

    # api.set_response_header('Content-Type', 'text/plain; charset=utf-8')
    # api.pretty_print(environ)
    # api.out('\n\n')

    if environ['REQUEST_METHOD'] == 'POST':
        # handle CSRF token
        transactions_enabled = 1

    args, kwargs = api.request_args, api.request_kwargs

    if 'submit' in kwargs:
        del kwargs['submit']

    service_name = 'core.render_object'
    format = 'html'
    slot_only = False

    if args and args[0].startswith('.'):
        service_name = args[0].lstrip('.')
        args = args[1:]

    if args and args[-1] in ('index.rss', 'index.json'):
        format = args[-1].split('.')[-1]
        args = args[:-1]

    if args and args[-1] == '_slot_only':
        slot_only = True
        args = args[:-1]

    page_title = ''
    kwargs.update(builtins)

    try:

        if service_name not in SERVICE_REGISTRY:
            raise NotFound(service_name)

        api.service_name = service_name

        service = SERVICE_REGISTRY[service_name]
        slot = SLOT_REGISTRY[service_name]
        renderer = RENDERER_REGISTRY[service_name]
        page_title = TITLE_REGISTRY[service_name]
        data = service(api, *args, **kwargs) or {}

        if 'finish_publishing' in data:
            return

        output = data.get('return_value', '')
        kwargs.update(data)

        if renderer:
            output = renderer(api=api, **kwargs)

    except NotFound, msg:
        response.set_response_status(404)
        output = ERROR_404_TEMPLATE
        slot = 'content_slot'
    except UnAuth, msg:
        response.set_response_status(401)
        output = ERROR_401_TEMPLATE % msg
        slot = 'content_slot'
    except Redirect:
        raise
    except Exception:
        response.set_response_status(500)
        logging.error(''.join(format_exception(*sys.exc_info())))
        output = ERROR_500_TEMPLATE % ''.join(format_traceback(*sys.exc_info()))
        slot = 'content_slot'

    if not environ.get('HTTP_X_REQUESTED_WITH') and (not slot_only):
        kwargs[slot] = output
        kwargs['page_title'] = page_title
        output = render_genshi_template('main', api=api, **kwargs)

    api.out(output)

def handle_http_options_request(environ, response):
    """Handle an HTTP OPTIONS request."""

    return response.set_header(
        'Allow', ', '.join(HTTP_HANDLERS.keys())
        )

register_http_handler('GET', handle_http_request)
register_http_handler('HEAD', handle_http_request)
register_http_handler('POST', handle_http_request)
register_http_handler('OPTIONS', handle_http_options_request)

# ------------------------------------------------------------------------------
# kore servise dekorator
# ------------------------------------------------------------------------------

def register_service(
    name, renderer=None, slot='content_slot', validators=None, title=''
    ):
    """Decorate a function with service-enabled behaviour."""

    def decorate_function(func):

        if name in SERVICE_REGISTRY:
            raise Error("Service already exists: %r" % name)

        SLOT_REGISTRY[name] = slot
        TITLE_REGISTRY[name] = title

        if isinstance(renderer, basestring):
            _renderer = func.__name__
        else:
            _renderer = renderer

        RENDERER_REGISTRY[name] = _renderer
        SERVICE_REGISTRY[name] = func

        return func

    return decorate_function

# ------------------------------------------------------------------------------
# genshi template handlers
# ------------------------------------------------------------------------------

GENSHI_TEMPLATE_CACHE = {}

if DEBUG_MODE:

    GENSHI_MTIME_DATA = {}

    def get_genshi_template(name, klass=MarkupTemplate):

        filepath = join_path(TEMPLATE_DIRECTORY, name+'.genshi')
        template_time = getmtime(filepath)

        if ((template_time <= GENSHI_MTIME_DATA.get(name, 0)) and
            (name in GENSHI_TEMPLATE_CACHE)):
            return GENSHI_TEMPLATE_CACHE[name]

        template = klass(open(filepath, 'U'), filepath, name)

        GENSHI_TEMPLATE_CACHE[name] = template
        GENSHI_MTIME_DATA[name] = template_time

        return template

else:

    def get_genshi_template(name, klass=MarkupTemplate):

        if name in GENSHI_TEMPLATE_CACHE:
            return GENSHI_TEMPLATE_CACHE[name]

        filepath = join_path(TEMPLATE_DIRECTORY, name+'.genshi')
        template_data = open(filepath, 'U')

        return GENSHI_TEMPLATE_CACHE.setdefault(
            name, klass(template_data, filepath, name)
            )

def call_genshi_template(template, template_mode='xhtml', **kwargs):
    return template.generate(**kwargs).render(template_mode)

def render_genshi_template(template_name, **kwargs):
    return get_genshi_template(template_name).generate(**kwargs).render('xhtml')

# ------------------------------------------------------------------------------
# text indexing
# ------------------------------------------------------------------------------

MIN_WORD_LENGTH = 3

STOP_WORDS = {

    'en': frozenset([

        'a', 'about', 'according', 'accordingly', 'affected', 'affecting',
        # 'after',
        'again', 'against', 'all', 'almost', 'already', 'also', 'although',
        'always', 'am', 'among', 'an', 'and', 'any', 'anyone', 'apparently', 'are',
        'arise', 'as', 'aside', 'at',
        # 'away',
        'be', 'became', 'because', 'become',
        'becomes', 'been', 'before', 'being', 'between', 'both', 'briefly', 'but',
        'by', 'came', 'can', 'cannot', 'certain', 'certainly', 'could', 'did', 'do',
        'does', 'done', 'during', 'each', 'either', 'else', 'etc', 'ever', 'every',
        'following', 'for', 'found', 'from', 'further', 'gave', 'gets', 'give',
        'given', 'giving', 'gone', 'got', 'had', 'hardly', 'has', 'have', 'having',
        'here', 'how', 'however', 'i', "i'm", 'if', 'in', 'into', 'is', 'it', 'its',
        "it's", 'itself',
        # 'just',
        'keep', 'kept', 'knowledge', 'largely', 'like', 'made', 'mainly',
        'make', 'many', 'might', 'more', 'most', 'mostly', 'much', 'must', 'nearly',
        'necessarily', 'neither', 'next', 'no', 'none', 'nor', 'normally', 'not',
        'noted', 'now', 'obtain', 'obtained', 'of', 'often', 'on', 'only', 'or',
        'other', 'our', 'out', 'owing', 'particularly', 'past', 'perhaps', 'please',
        'poorly', 'possible', 'possibly', 'potentially', 'predominantly', 'present',
        'previously', 'primarily', 'probably', 'prompt', 'promptly', 'put',
        'quickly', 'quite', 'rather', 'readily', 'really', 'recently', 'regarding',
        'regardless', 'relatively', 'respectively', 'resulted', 'resulting',
        'results', 'said', 'same', 'seem', 'seen', 'several', 'shall', 'should',
        'show', 'showed', 'shown', 'shows', 'significantly', 'similar', 'similarly',
        'since', 'slightly', 'so', 'some', 'sometime', 'somewhat', 'soon',
        'specifically',
        # 'state',
        'states', 'strongly', 'substantially',
        'successfully', 'such', 'sufficiently', 'than', 'that', 'the', 'their',
        'theirs', 'them', 'then', 'there', 'therefore', 'these', 'they', 'this',
        'those', 'though', 'through', 'throughout', 'to', 'too', 'toward', 'under',
        'unless', 'until', 'up', 'upon', 'use', 'used', 'usefully', 'usefulness',
        'using', 'usually', 'various', 'very', 'was', 'we', 'were', 'what', 'when',
        'where', 'whether', 'which', 'while', 'who', 'whose', 'why', 'widely',
        'will', 'with', 'within', 'without', 'would', 'yet', 'you'
        ])

    }

# find_all_words = re.compile(r'(?u)\w+').findall # (?L)\w+

find_all_words = compile_regex(
    r'[^\s!\"#$%&()*+,-./:;<=>?@\[\\^_`{|}~]*'
    ).findall

HTML_PATTERNS = (
    # cdata
    compile_regex(r'<!\[CDATA\[((?:[^\]]+|\](?!\]>))*)\]\]>').sub,
    # comment
    compile_regex(r'<!--((?:[^-]|(?:-[^-]))*)-->').sub,
    # pi
    compile_regex(r'<\?(\S+)[\t\n\r ]+(([^\?]+|\?(?!>))*)\?>').sub,
    # doctype
    compile_regex(r'(?m)(<!DOCTYPE[\t\n\r ]+\S+[^\[]+?(\[[^\]]+?\])?\s*>)').sub,
    # entities
    compile_regex(r'&[A-Za-z]+;').sub,
    # tag
    compile_regex(r'(?ms)<[^>]+>').sub,
    # re.compile(r'<[^<>]*>').sub,
    )

def harvest_words(
    text, ignore_html=True, min_word_length=MIN_WORD_LENGTH,
    stop_words=STOP_WORDS, html_patterns=HTML_PATTERNS,
    find_words_in_text=find_all_words
    ):
    """
    Harvest words from the given ``text``.

      >>> text = "hello <tag>&nbsp;world. here! there, is a ain't 'so' \
      ...   it \"great hello '   '?"

    """ # emacs'

    if ignore_html:
        for replace_html in html_patterns:
            text = replace_html(' ', text)

    text = text.lower() # @/@ handle i18n ??
    words = set(); add_word = words.add

    for word in find_words_in_text(text):

        while word.startswith("'"):
            word = word[1:]
        while word.endswith("'"):
            word = word[:-1]

        if (len(word) > min_word_length) and (word not in stop_words):
            add_word(word)

    return list(words)

# ------------------------------------------------------------------------------
# plex link syntax
# ------------------------------------------------------------------------------

replace_links = compile_regex(r'[^\\]\[\[(.*?)[^\\]\]\]').sub

def _handle_links(content):
    pass

def handle_links(content):
    return replace_links(content, _handle_links)

# ------------------------------------------------------------------------------
# utility functions
# ------------------------------------------------------------------------------

def get_oauth_service_key(service, cache={}):
    if service in cache: return cache[service]
    return cache.setdefault(
        service, "%s&" % encode(OAUTH_APP_SETTINGS[service]['consumer_secret'])
        )

def create_uuid():
    return 'id-%s' % uuid4()

def encode(text):
    return urlquote(str(text), '')

def twitter_specifier_handler(client):
    return client.get('/account/verify_credentials')['screen_name']

OAUTH_APP_SETTINGS['twitter']['specifier_handler'] = twitter_specifier_handler

# ------------------------------------------------------------------------------
# oauth db entities
# ------------------------------------------------------------------------------

class OAuthRequestToken(db.Model):
    """OAuth Request Token."""

    service = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class OAuthAccessToken(db.Model):
    """OAuth Access Token."""

    service = db.StringProperty()
    specifier = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

# ------------------------------------------------------------------------------
# oauth client
# ------------------------------------------------------------------------------

class OAuthClient(object):
    """OAuth client."""

    __public__ = ('callback', 'cleanup', 'login', 'logout')

    def __init__(self, webapp_api, service, oauth_callback=None, **request_params):
        self.service = service
        self.service_info = OAUTH_APP_SETTINGS[service]
        self.service_key = None
        self.webapp_api = webapp_api
        self.request_params = request_params
        self.oauth_callback = oauth_callback
        self.token = None
        self.cookie_name = 'oauth.%s' % service

    # public methods

    def get(self, api_method, **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            self.token = OAuthAccessToken.get_by_key_name(
                self.webapp_api.get_cookie(self.cookie_name)
                )

        fetch = urlfetch(self.get_signed_url(
            api_method, self.token, **extra_params
            ))

        if fetch.status_code != 200:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return decode_json(fetch.content)

    def login(self):

        proxy_id = self.webapp_api.get_cookie(self.cookie_name)

        if proxy_id:
            return "FOO%rFF" % proxy_id
            self.webapp_api.expire_cookie(self.cookie_name)

        return self.get_request_token()

    def logout(self, return_to='/'):
        self.webapp_api.expire_cookie(self.cookie_name)
        raise Redirect(self.webapp_api.request_kwargs.get("return_to", return_to))

    # oauth workflow

    def get_request_token(self):

        token_info = self.get_data_from_signed_url(
            self.service_info['request_token_url'], **self.request_params
            )

        token = OAuthRequestToken(
            service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        token.put()

        if self.oauth_callback:
            oauth_callback = {'oauth_callback': self.oauth_callback}
        else:
            oauth_callback = {}

        raise Redirect(self.get_signed_url(
            self.service_info['user_auth_url'], token, **oauth_callback
            ))

    def callback(self, return_to='/'):

        oauth_token = self.webapp_api.request_kwargs.get("oauth_token")

        if not oauth_token:
            return get_request_token()

        oauth_token = OAuthRequestToken.all().filter(
            'oauth_token =', oauth_token).filter(
            'service =', self.service).fetch(1)[0]

        token_info = self.get_data_from_signed_url(
            self.service_info['access_token_url'], oauth_token
            )

        key_name = create_uuid()

        self.token = OAuthAccessToken(
            key_name=key_name, service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        if 'specifier_handler' in self.service_info:
            specifier = self.token.specifier = self.service_info['specifier_handler'](self)
            old = OAuthAccessToken.all().filter(
                'specifier =', specifier).filter(
                'service =', self.service)
            db.delete(old)

        self.token.put()

        self.webapp_api.set_cookie(
            self.cookie_name, key_name, expires="Fri, 31-Dec-2021 23:59:59 GMT"
            )

        raise Redirect(return_to)

    def cleanup(self):
        query = OAuthRequestToken.all().filter(
            'created <', datetime.now() - EXPIRATION_WINDOW
            )
        count = query.count(CLEANUP_BATCH_SIZE)
        db.delete(query.fetch(CLEANUP_BATCH_SIZE))
        return "Cleaned %i entries" % count

    # request marshalling

    def get_data_from_signed_url(self, __url, __token=None, __meth='GET', **extra_params):
        return urlfetch(self.get_signed_url(
            __url, __token, __meth, **extra_params
            )).content

    def get_signed_url(self, __url, __token=None, __meth='GET',**extra_params):

        service_info = self.service_info

        kwargs = {
            'oauth_consumer_key': service_info['consumer_key'],
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_version': '1.0',
            'oauth_timestamp': int(time()),
            'oauth_nonce': getrandbits(64),
            }

        kwargs.update(extra_params)

        if self.service_key is None:
            self.service_key = get_oauth_service_key(self.service)

        if __token is not None:
            kwargs['oauth_token'] = __token.oauth_token
            key = self.service_key + encode(__token.oauth_token_secret)
        else:
            key = self.service_key

        message = '&'.join(map(encode, [
            __meth.upper(), __url, '&'.join(
                '%s=%s' % (encode(k), encode(kwargs[k])) for k in sorted(kwargs)
                )
            ]))

        kwargs['oauth_signature'] = hmac(
            key, message, sha1
            ).digest().encode('base64')[:-1]

        return '%s?%s' % (__url, urlencode(kwargs))

# ------------------------------------------------------------------------------
# twitter client
# ------------------------------------------------------------------------------

class TwitterClient(object):
    """Twitter client for the official API."""

    def __init__(self, username=None, password=None, oauth=None):
        pass

# ------------------------------------------------------------------------------
# kore data types
# ------------------------------------------------------------------------------

class TwitterUser(db.Model):
    """A Twitter User."""

class Tweet(db.Model):
    """A Tweet."""

class TweetBookKeeping(db.Model):
    """Bookkeeping for Tweets."""

# ------------------------------------------------------------------------------
# self runner -- app engine cached main() function
# ------------------------------------------------------------------------------

def main():
    import source.main
    run_wsgi_app(Application)

# ------------------------------------------------------------------------------
# run in standalone mode
# ------------------------------------------------------------------------------

if __name__ == '__main__':
    main()
