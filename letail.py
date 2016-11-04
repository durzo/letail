#!/usr/bin/python
import os
import sys
import requests
import requests.utils
import pickle
from getpass import getpass
import json
from termcolor import colored
from time import time,sleep
from datetime import datetime
import re
import click
import ConfigParser
from appdirs import user_config_dir

session = requests.Session()

CONFIG = ConfigParser.ConfigParser()
CONFIG_FILE_PATH = os.path.join(user_config_dir("lecli"), 'config.ini')

def get_named_logkey(name):
    files_read = CONFIG.read(CONFIG_FILE_PATH)
    if len(files_read) != 1:
        print "lecli config file not found, cannot use named log keys"
        return None
    section = 'LogNicknames'
    try:
        named_logkeys = dict(CONFIG.items(section))
        name = name.lower()
        if name in named_logkeys:
            logkey = (named_logkeys[name],)
            if len(logkey[0]) != 36:
                print "Error: Named Logkey (%s) = '%s' is not of correct length in section: '%s' of " \
                      "your configuration file: '%s'" % (name, logkey, section, CONFIG_FILE_PATH)
            else:
                return logkey
        else:
            print "Error: Configuration key for Named Logkey (%s) was not found in configuration file (%s) in '%s' " \
                  "section" % (name, CONFIG_FILE_PATH, section)
    except ConfigParser.NoSectionError:
        print "Error: Section '%s' was not found in configuration file(%s)" % (section, CONFIG_FILE_PATH)

def get_cookies():
    global session
    print "Searching for saved cookie file"
    try:
        with open(os.environ['HOME'] + '/.logentries_cookies.dat') as f:
            print "Found saved cookies, creating cookie jar"
            jar = requests.utils.cookiejar_from_dict(pickle.load(f))
            session.cookies = jar
    except:
        print "No cookies found, logging in..."
        login()


def login():
    global session
    jar = requests.cookies.RequestsCookieJar()
    session.cookies = jar
    url = 'https://logentries.com/login/'
    print "Requesting login page..."
    r = session.get(url)
    url = 'https://logentries.com/login/ajax/'
    loginpacket = {}
    loginpacket['csrfmiddlewaretoken'] = get_unique_cookie('csrftoken')
    loginpacket['ajax'] = "1"
    loginpacket['next'] = "%2Fapp%2F"
    loginpacket['username'] = raw_input('Logentries username: ')
    loginpacket['password'] = getpass()
    loginpacket['remember_me'] = "on"
    r = session.post(url, headers={'referer': "https://logentries.com/login/"}, data=loginpacket)
    if r.status_code is 200:
        print "Login Successfull, saving cookies to file"
        jar = r.cookies
        with open(os.environ['HOME'] + '/.logentries_cookies.dat', 'w') as f:
            pickle.dump(requests.utils.dict_from_cookiejar(jar), f)
        return jar
    else:
        print "Bad code returned from LE: %s" % r.status_code
        print "Headers: %s" % r.headers
        sys.exit(1)


def get_data():
    global session
    url = 'https://logentries.com/app/'
    headers = {}
    headers['Pragma'] = 'no-cache'
    good_hook = False
    while not good_hook:
        print "Obtaining appid and user key..."
        try:
            session.cookies.clear(domain='', path='/', name='csrftoken')
        except:
            pass
        try:
            r = session.get(url, headers=headers, timeout=5)
        except Exception as e:
            print "Error: %s" % e
            sys.exit(1)
        if r.status_code is not 200:
            print "Bad return code from LE: %s" % r.status_code
            print "Headers: %s" % r.headers
        good_hook = True
    match = re.search('(?:<code id="account-account-key-placeholder">)(?P<accountkey>[a-z0-9-]{36})(?:<\/code>)', r.text)
    data = {}
    try:
        data['user_key'] = match.group('accountkey')
        data['appid'] = data['user_key'][0:8]
    except:
        print "Unable to find appid and user key, aborting."
        sys.exit(1)
    return data


def get_unique_cookie(cookie):
    global session
    try:
        return session.cookies.get(cookie)
    except requests.cookies.CookieConflictError:
        print "removing duplicate cookie"
        session.cookies.clear(domain='', path='/', name=cookie)
    return session.cookies.get(cookie)


def enable_tail(sources, user_key, appid):
    global session
    start_time = int(time())
    good_hook = False
    while not good_hook:
        #print "Enable live tail mode..."
        url = 'https://logentries.com/api/'
        data = {}
        data['request'] = 'enable_tail'
        data['sources'] = sources
        data['user_key'] = user_key
        headers = {}
        headers['X-CSRFToken'] = get_unique_cookie('csrftoken')
        headers['Referer'] = "https://logentries.com/app/%s" % appid
        headers['Origin'] = 'https://logentries.com'
        headers['Pragma'] = 'no-cache'
        try:
            r = session.post(url, headers=headers, data=data, timeout=5)
        except: 
            continue
        if r.status_code is not 200:
            print "Bad return code: %s" % r.status_code
            print "Headers: %s" % r.headers
            print "Body: %s" % r.text
        good_hook = True
    return start_time


def tail(sources, appid, epochnow, from_sn=0, search=''):
    global session
    url = 'https://logentries.com/api/tail/'
    data = {}
    data['sources'] = sources
    data['filter'] = search
    data['from_sn'] = from_sn
    data['limit'] = '80'
    data['tag'] = '0'
    data['tail'] = 'true'
    data['from'] = epochnow
    data['to'] = '-1'
    headers = {}
    headers['X-CSRFToken'] = get_unique_cookie('csrftoken')
    headers['Referer'] = "https://logentries.com/app/%s" % appid
    headers['Origin'] = 'https://logentries.com'
    headers['Pragma'] = 'no-cache'
    r = session.post(url, headers=headers, data=data)
    if r.status_code is not 200:
      print "Bad return code %s" % r.status_code
      sys.exit(1)
    try:
        ledata = json.loads(r.text)
        return ledata
    except ValueError:
        print "Data not in JSON format: %d '%s'" % ( len(r.text), r.text)


@click.command()
@click.option('-e', '--expand', is_flag=True, help='Expand JSON')
@click.option('-q', '--query', default='', help='Query to filter on')
@click.option('-s', '--sources', default='', help='Log Source ID, can also use named log keys from lecli')

def run(expand, query, sources):
    dt = datetime.now()
    ms = dt.strftime('%s%%06d') % dt.microsecond 
    epochnow = ms[0:13]
    if not re.match('^[a-z0-9-]{36}$', sources):
        sources = get_named_logkey(sources)
    if sources is None:
        print "No valid log key source provided, use -s or see --help"
        sys.exit(1)
    get_cookies()
    data = get_data()
    print "Enabling Live Tail"
    start_time = enable_tail(sources, data['user_key'], data['appid'])
    print ""
    from_sn = 0

    while True:
        ledata = tail(sources, data['appid'], epochnow, from_sn, query)
        if ledata['first_sn'] < 0:
            poll_time = int(start_time) + 5
            if time() > poll_time:
                start_time = enable_tail(sources, data['user_key'], data['appid'])
            #else:
            #    print "no data, polling again"
            continue
        else:
            epochnow = ledata['first_ts']
            from_sn = ledata['first_sn'] + 1
            for event in sorted(ledata['events'], key=lambda items: items['s']):
                time_value = datetime.fromtimestamp(event['t'] / 1000)
                human_ts = time_value.strftime('%Y-%m-%d %H:%M:%S')
                if expand:
                    try:
                        message = json.loads(event['m'])
                        print colored(str(human_ts), 'red') + '\t' + \
                              colored(json.dumps(message, indent=4, separators={':', ';'}), 'white')
                    except ValueError:
                        print colored(str(human_ts), 'red') + '\t' + colored(event['m'], 'white')
                        print ""
                else:
                    print colored(str(human_ts), 'red') + '\t' + colored(event['m'], 'white')
                    print ""


if __name__ == '__main__':
    run()
