========
TweetApp
========

Development is still happening and will stabilise before the end of February.
Follow @tav on http://twitter.com/tav to keep up to date. Will have some
documentation up by that time too...

A framework for creating Twitter apps on Google App Engine.

See the ``old`` directory for a standalone webapp oauth handler for Twitter.

--------------------------------------------------------------------------------

# THIS DOCUMENTATION IS NOT ACCURATE YET... IT WILL BE BY THE END OF FEB. THX!

To start developing with TweetApp, grab the code::

  $ git clone git://github.com/tav/tweetapp.git

Unzip the latest App Engine SDK as ``google_appengine`` inside the directory::

  $ cd tweetapp
  $ curl -O http://googleappengine.googlecode.com/files/google_appengine_1.1.9.zip
  $ unzip google_appengine_1.1.9.zip
  $ rm google_appengine_1.1.9.zip

Copy over the ``.in`` files and edit them to suit your app::

  $ cp app/source/config.py.in app/source/config.py

Likewise with the default ``app/app.yaml``.

You define services in ``app/source/main.py`` which is imported by
``app/root.py`` on startup.

Test your app locally by running the dev_appserver, run.sh provides a wrapper::

  $ ./bin/run.sh

You can pass additional parameters to it, e.g.::

  $ ./bin/run.sh --port=8001 --require_indexes
  $ ./bin/run.sh --help

And, once you are happy with the app, deploy it using::

  $ ./bin/update.sh
