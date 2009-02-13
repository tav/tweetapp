#! /bin/sh

echo "APPLICATION_TIMESTAMP = `python -c "from time import time; print time()"`" > source/updated.py
./google_appengine/appcfg.py -v update source
