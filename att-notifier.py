#!/usr/bin/env python3

import requests
import hashlib
import configparser
import sys
import sqlite3
import subprocess
import os
import time
import datetime
import holidays
import urllib

from threading import Thread
from tabulate import tabulate
from flask import Flask, request
from flask.views import View


class Att_notify(View):

    def __init__(self):

        self.config_file_path = '/etc/online_checker/online_checker.conf'
        self.log_file_path = '/var/log/online_checker.log'
        self.config = configparser.ConfigParser()

        try:
            self.config.read_file(open(self.config_file_path))
            self.image_format = self.config.get('DEFAULT', 'image_format')
            self.directory = self.config.get('DEFAULT', 'directory')
            self.offline_md5 = self.config.get('DEFAULT', 'offline_md5')
            self.online_md5 = self.config.get('DEFAULT', 'online_md5')
            self.busy_md5 = self.config.get('DEFAULT', 'busy_md5')
            self.debug = self.config.getboolean('DEFAULT', 'debug')
            self.connection_host = self.config.get('DEFAULT', 'host')
            self.connection_port = self.config.getint('DEFAULT', 'port')
            self.trygetstatus = self.config.getint('DEFAULT', 'trygetstatus')
            self.db_name = self.config.get('SQLITE', 'db_name')
            self.db_path = self.config.get('SQLITE', 'db_path')
            self.update_timeout = self.config.getint('SQLITE',
                                                     'update_timeout')
            self.channel_id = self.config.get('SLACK', 'channel_id')
            self.hook = self.config.get('SLACK', 'hook')

        except (configparser.NoOptionError,
                subprocess.CalledProcessError) as noe:
            msg = '%s has incorrect or missing values %s'\
                   % (self.config_file_path, noe)
            current_date = datetime.datetime.now()

            with open(self.log_file_path, 'a') as debug_err:
                debug_err.write('%s: [CRITICAL] %s\n' % (current_date, msg))

            sys.exit()

        except configparser.Error as e:
            msg = 'Error reading %s %s' % (self.config_file_path, e)
            current_date = datetime.datetime.now()

            with open(self.log_file_path, 'a') as debug_err:
                debug_err.write('%s: [CRITICAL] %s\n' % (current_date, msg))

            sys.exit()

        except FileNotFoundError:
            msg = 'File not found %s' % self.log_file_path
            current_date = datetime.datetime.now()

            with open(self.log_file_path, 'a') as debug_err:
                debug_err.write('%s: [CRITICAL] %s\n' % (current_date, msg))

            sys.exit()

        self.app = Flask(__name__)
        self.help_mes = """
Help content:

    "user_list" - displays list of users.

    "user_add" - adds new user.
     necessary args: "user_id", "state", "hours", "weekends", "slack_id"
     example: user_add user_id=js007a state=enabled hours=08:00-17:00
     weekends=Sat,Sun slack_id=jsmith

    "user_mod" - modifies users.
     necessary args: "user_id" and any of:
     "state", "hours", "weekends", "slack_id"
     example: user_mod user_id=js007a state=disabled hours=10:00-19:00

    "user_del" - deletes users and needs only "user_id" arg.
     example: user_del user_id=js007a"""

    def DEBUG(self, msg):

        if self.debug:
            current_date = datetime.datetime.now()
            with open(self.log_file_path, 'a') as debug_err:
                debug_err.write('%s: [DEBUG] %s\n' % (current_date, msg))

    def check_db(self):
        if not os.path.isdir(self.db_path):
            self.DEBUG('Can not read/write in the directory "%s".'
                       % self.db_path)
            sys.exit()

        elif not os.path.isfile(self.db_path+self.db_name):
            self.DEBUG('Can not find the database in "%s",\
                       creating new database.' %
                       (self.db_path+self.db_name))
            conn = sqlite3.connect(self.db_path + self.db_name)
            c = conn.cursor()
            c.execute('''CREATE TABLE users
                      (user_id, status, state, hours, weekends,\
                      working, slack_id, ping)''')

            conn.commit()
            conn.close()

    def user_add(self, args_lst):

        select_users = "select user_id from users where user_id = '%s'"
        insert_values = "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ping = 0
        status = ''
        working = ''
        conn = sqlite3.connect(self.db_path+self.db_name)
        c = conn.cursor()
        check_user = c.execute(select_users % args_lst['user_id']).fetchone()

        if not check_user:
            c.execute(insert_values, (args_lst['user_id'],
                                      status,
                                      args_lst['state'],
                                      args_lst['hours'],
                                      args_lst['weekends'],
                                      working,
                                      args_lst['slack_id'],
                                      ping))
            conn.commit()
            conn.close()
            self.DEBUG('User "%s" has been added!' % args_lst['user_id'])
            return 'User "%s" has been added!' % args_lst['user_id']

        conn.close()
        self.DEBUG('User "%s" already exist!' % args_lst['user_id'])
        return 'User "%s" already exist!' % args_lst['user_id']

    def user_del(self, args_lst):

        select_users = "select user_id from users where user_id = '%s'"
        delete_users = "DELETE FROM users where user_id = '%s'"
        conn = sqlite3.connect(self.db_path+self.db_name)
        c = conn.cursor()
        check_user = c.execute(select_users % args_lst['user_id']).fetchone()

        if check_user:
            c.execute(delete_users % args_lst['user_id'])
            conn.commit()
            conn.close()
            self.DEBUG('User "%s" has been deleted!' % args_lst['user_id'])
            return 'User "%s" has been deleted!' % args_lst['user_id']

        conn.close()
        self.DEBUG('User "%s" does not exist!' % args_lst['user_id'])
        return 'User "%s" does not exist!' % args_lst['user_id']

    def user_mod(self, args_lst):

        flag = True
        select_allusers = "select * from users where user_id = '%s'"
        select_user = "select %s from users where user_id = '%s'"
        update_users = "UPDATE users SET '%s' = '%s' where user_id = '%s'"
        conn = sqlite3.connect(self.db_path+self.db_name)
        c = conn.cursor()
        check_user = c.execute(select_allusers
                               % args_lst['user_id']).fetchone()

        if check_user:
            for parm in args_lst.keys():
                get_item = c.execute(select_user
                                     % (parm, args_lst['user_id']))\
                                     .fetchone()[0]

                if args_lst[parm] != get_item:
                    c.execute(update_users % (parm, args_lst[parm],
                                              args_lst['user_id']))
                    flag = False
        else:
            self.DEBUG('User "%s" does not exist!' % args_lst['user_id'])
            return 'User "%s" does not exist!' % args_lst['user_id']

        if not flag:
            conn.commit()
            conn.close()
            self.DEBUG('User "%s" has been modified!' % args_lst['user_id'])
            return 'User "%s" has been modified!' % args_lst['user_id']

        conn.close()
        self.DEBUG('Nothing was change, old and new attributes are equal.')
        return 'Nothing was change, old and new attributes are equal.'

    def user_list(self):

        fields = ['id ', 'status', 'state', 'hours', 'weekends', 'at work',
                  'slack id', 'ping']
        conn = sqlite3.connect(self.db_path+self.db_name)
        c = conn.cursor()
        usrlst = c.execute("select * from users").fetchall()
        conn.close()

        output = tabulate(list(map(lambda x: list(x)[:-1], usrlst)),
                          headers=fields, tablefmt='orgtbl')

        return output

    def user_check(self, user):

        url = '%s%s.%s' % (self.directory, user, self.image_format)

        try:
            get_hash = hashlib.md5(urllib.request.urlopen(url).read())\
                       .hexdigest()
        except urllib.error.URLError:
            self.DEBUG('Can not get user %s connection issue.' % user)
            return 'bad connection'
        except urllib.error.HTTPError:
            self.DEBUG('User %s, user not found.' % user)
            return 'not found'

        if get_hash == self.offline_md5:
            self.DEBUG('User %s offline.' % user)
            return 'offline'
        elif get_hash == self.online_md5:
            self.DEBUG('User %s online.' % user)
            return 'online'
        elif get_hash == self.busy_md5:
            self.DEBUG('User %s busy.' % user)
            return 'busy'

        self.DEBUG('User %s status uknown.' % user)
        return 'unknown'

    def scheduler(self, hours, weekends):

        current = datetime.datetime.now()
        start, stop = hours.split('-')
        s_h, s_m = list(map(int, start.split(':')))
        e_h, e_m = list(map(int, stop.split(':')))
        p_y, p_m, p_d = list(map(int, current.strftime("%Y %m %d").split()))

        if s_h <= e_h:
            past = datetime.datetime(p_y, p_m, p_d, s_h, s_m)
            future = datetime.datetime(p_y, p_m, p_d, e_h, e_m)
        else:
            past = datetime.datetime(p_y, p_m, p_d, s_h, s_m)
            future = datetime.datetime(p_y, p_m, p_d + 1, e_h, e_m)

        w_e = weekends.split(',')
        c_w = current.strftime("%A")[:3]
        rest = holidays.US().get(datetime.datetime.now())

        if rest is None and past <= current < future and c_w not in w_e:
            return True

        return False

    def status_update(self, c, status, state, hours,
                      weekends, user_id, sql_req):

        if state == 'enabled' and self.scheduler(hours, weekends) is True:
            return c.execute(sql_req % (status, 'yes', 0, user_id))
        else:
            return c.execute(sql_req % (status, 'no', 0, user_id))

    def db_refresh(self, update_timeout):

        sql_req = "UPDATE users SET status = '%s', working = '%s',\
                  ping = %s  where user_id = '%s'"
        data = "{'text':'<@%s>: Please login in \"Q\" chat !'}"
        get_parm = "select user_id, state, hours, weekends, working,\
                   slack_id, ping from users"

        while True:
            conn = sqlite3.connect(self.db_path+self.db_name)
            c = conn.cursor()
            usr_lst = c.execute(get_parm).fetchall()

            for item in usr_lst:
                user_id, state, hours, weekends, working, slack_id, ping = item
                status = self.user_check(user_id)

                if status == 'online':
                    self.status_update(c, status, state, hours, weekends,
                                       user_id, sql_req)

                elif status == 'offline':
                    if state == 'enabled' and self.scheduler(hours,
                                                             weekends) is True:
                        if ping % self.trygetstatus == 0:
                            requests.post(self.hook, data=data % slack_id,
                                          headers={'Content-type':
                                                   'application/json'})
                        c.execute(sql_req % (status, 'yes', ping + 1, user_id))
                    else:
                        c.execute(sql_req % (status, 'no', 0, user_id))

                elif status == 'busy':
                    self.status_update(c, status, state,
                                       hours, weekends, user_id, sql_req)

                elif status == 'bad connection':
                    self.status_update(c, status, state,
                                       hours, weekends, user_id, sql_req)

                elif status == 'not found':
                    self.status_update(c, status, state,
                                       hours, weekends, user_id, sql_req)

                elif status == 'unknown':
                    self.status_update(c, status, state,
                                       hours, weekends, user_id, sql_req)

            conn.commit()
            conn.close()
            time.sleep(self.update_timeout)

    def dispatch_request(self):

        args_lst = {}
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        arguments = ['user_id', 'state', 'weekends', 'slack_id', 'hours']
        commands = ['user_list', 'user_add', 'user_del', 'user_mod', 'help']
        get_channel_id = request.form.get('channel_id')

        if get_channel_id != self.channel_id:
            self.DEBUG('Authorization error for channel_id = %s'
                       % get_channel_id)
            return "Authorization error!"

        text = request.form.get('text')
        filtered = text.split()
        command = filtered[0]

        if command not in commands:
            self.DEBUG('Wrong command!')
            return 'Wrong command!'

        for arg in filtered[1:]:
            splited = arg.split('=')
            if splited[0] == "user_id":
                for item in splited[1]:
                    if item.isalnum() is False:
                        self.DEBUG('Incorrect "user_id"!')
                        return 'Incorrect "user_id"!'
            elif splited[0] == "state":
                if splited[1] not in ["enabled", "disabled"]:
                    self.DEBUG('Wrong state!')
                    return 'Wrong state!'
            elif splited[0] == "weekends":
                days = splited[1].split(',')
                for day in days:
                    if day not in ['Mon', 'Tue', 'Wed',
                                   'Thu', 'Fri', 'Sat', 'Sun']:
                        self.DEBUG('Wrong weekdays!')
                        return 'Wrong weekdays!'
            elif splited[0] == "slack_id":
                for item in splited[1]:
                    if item.isalnum() is False:
                        self.DEBUG('Incorrect "slack_id"!')
                        return 'Incorrect "slack_id"!'
            elif splited[0] == "hours":
                period = splited[1].split('-')
                if len(period) != 2:
                    self.DEBUG('wrong time!')
                    return "wrong time!"
                st, et = period
                st_h, st_m = st.split(':')
                et_h, et_m = et.split(':')

                for item in [st_h, st_m, et_h, et_m]:
                    if item.isdigit() is False or len(item) != 2:
                        self.DEBUG('wrong time!')
                        return "wrong time!"

                if int(st_h) > 23 or int(et_h) > 23 or int(st_m) > 59\
                   or int(et_m) > 59:
                    self.DEBUG('wrong time!')
                    return 'wrong time!'

            else:
                self.DEBUG('wrong arguments!')
                return 'Wrong arguments!'

            args_lst[splited[0]] = splited[1]

        if command == 'user_list':
            self.DEBUG('Command user_list passed.')
            return '```%s %s\n\n%s```' % (current_time,
                                          'List of users:', self.user_list())
        elif command == 'user_mod' and 'user_id' in args_lst:
            self.DEBUG('Command user_mod passed.')
            return '```%s %s\n\n%s```' % (current_time,
                                          self.user_mod(args_lst),
                                          self.user_list())
        elif command == 'user_del' and 'user_id' in args_lst:
            self.DEBUG('Command user_del passed.')
            return '```%s %s\n\n%s```' % (current_time,
                                          self.user_del(args_lst),
                                          self.user_list())
        elif command == 'user_add':
            for _ in arguments:
                if _ not in args_lst:
                    print(_)
                    self.DEBUG('Not enough arguments for user_add.')
                    return 'Not enough arguments!'
            self.DEBUG('Command user_add passed.')
            return '```%s %s\n\n%s```' % (current_time,
                                          self.user_add(args_lst),
                                          self.user_list())
        elif command == 'help':
            return "```%s %s```" % (current_time, self.help_mes)
        else:
            self.DEBUG('Not enough arguments for input command.')
            return 'Not enough arguments!'

    def app_start(self):

        self.check_db()
        db_refresh_thread = Thread(target=self.db_refresh,
                                   args=[self.update_timeout])
        db_refresh_thread.start()
        self.app.add_url_rule('/', methods=['POST'],
                              view_func=self.as_view(__name__))
        return self.app.run(host=self.connection_host,
                            port=self.connection_port, debug=False)

if __name__ == '__main__':
    sys.exit(Att_notify().app_start())
