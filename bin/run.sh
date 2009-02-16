#! /bin/sh

tweetapp_root=$(dirname $(dirname $0))

$tweetapp_root/google_appengine/dev_appserver.py $@ $tweetapp_root/app

# Local SDK Admin URLs:

# http://localhost:8080/_ah/login
# http://localhost:8080/_ah/admin
