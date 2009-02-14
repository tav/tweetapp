========
TweetApp
========

A framework for creating Twitter apps on Google App Engine.

To start developing with TweetApp, grab the code::

  $ git clone git://github.com/tav/tweetapp.git

Unzip the latest App Engine SDK as ``google_appengine`` inside the directory::

  $ cd tweetapp
  $ curl -O http://googleappengine.googlecode.com/files/google_appengine_1.1.9.zip
  $ unzip google_appengine_1.1.9.zip
  $ rm google_appengine_1.1.9.zip

Copy over the ``.in`` files and edit them to suit your app::

  $ cp source/app.yaml.in source/app.yaml
  $ cp source/config.py.in source/config.py
  $ cp source/main.py.in source/main.py

You define services in ``main.py`` which is imported by ``root.py`` on startup.

Test your app locally by running the dev_appserver, run.sh provides a wrapper::

  $ ./run.sh

You can pass additional parameters to it, e.g.::

  $ ./run.sh --port=8001 --require_indexes
  $ ./run.sh --help

And, once you are happy with the app, deploy it using::

  $ ./update.sh
