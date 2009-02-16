#! /bin/sh

tweetapp_root=$(dirname $(dirname $0))

echo "APPLICATION_TIMESTAMP = `python -c "from time import time; print time()"`" > $tweetapp_root/app/source/updated.py
$tweetapp_root/google_appengine/appcfg.py -v update $tweetapp_root/app
