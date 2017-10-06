#!/usr/bin/env python

import json
import requests
import re
import logging
import logging.handlers
import sys
import os
import boto3
from time import sleep
from daemon import Daemon
import yaml
from urllib import quote_plus


with open('./reset-o-nator.yaml', 'r') as configfile:
    config = yaml.load(configfile)


def get_logger():
    logdir = config['logdir']
    if not os.path.exists(logdir):
        os.makedirs(logdir)
    # today = str(datetime.date.today())
    logfile = logdir + '/reset-o-nator.log'
    logformatter = logging.Formatter('%(asctime)s [reset-o-nator:%(funcName)s:%(lineno)d] [%(levelname)s] %(message)s')
    new_logger = logging.getLogger()
    new_logger.setLevel(logging.INFO)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)
    logging.getLogger('sqs_listener').setLevel(logging.ERROR)
    filehandler = logging.handlers.TimedRotatingFileHandler(logfile, when='midnight', interval=1, backupCount=14)
    filehandler.setFormatter(logformatter)
    filehandler.suffix = "%Y-%m-%d"
    new_logger.addHandler(filehandler)
    # If tty, also log to screen
    if sys.stdout.isatty():
        consolehandler = logging.StreamHandler()
        consolehandler.setFormatter(logformatter)
        new_logger.addHandler(consolehandler)
    return new_logger


logger = get_logger()


def route_message(message, message_id):
    site2rex = re.compile(config['site2']['regex'])
    site1rex = re.compile(config['site1']['regex'])
    try:
        compromised_on = message['compromised_on']
        email = message['email']
    except KeyError as err:
        logger.error('KeyError, missing or invalid key in message.'
                     ' message_id=\"{}\", error=\"{}\"'.format(message_id, err))
        return False
    else:
        logger.info('action=new_message, message_id=\"{}\", email=\"{}\",'
                    ' compromised_on=\"{}\"'.format(message_id, email, compromised_on))
        if site2rex.match(compromised_on):
            try:
                userid = message['userid']
            except KeyError as err:
                logger.error('KeyError, missing or invalid key in SITE2 message.'
                             ' action=message_error, message_id=\"{}\", error=\"{}\"'.format(message_id, err))
                return False
            else:
                return reset_site2_password(userid, compromised_on, email, message_id)
        elif site1rex.match(compromised_on):
            # process_site1(email, compromised_on, compromised_time)
            return process_site1_message(email, compromised_on, message_id)
        else:
            logger.error('Invalid \"compromised_on\" found, compromised_on=\"{}\",'
                         ' email=\"{}\", message_id=\"{}\", action=message_error, '
                         'error="Invalid site found in message"'.format(compromised_on, email,
                                                                        message_id))
            return False


def reset_site2_password(userid, sitecode, email, message_id):
    host = config['site2']['api_host']
    baseurl = config['site2']['baseurl']
    url = host + baseurl
    query = config['site2']['query'].format(sitecode, userid)
    headers = {'User-Agent': config['user_agent']}
    try:
        r = requests.get(url, params=query, headers=headers, )
        # r.raise_for_status() #Uncomment this if you want 4XX and 5XX errors to raise exceptions
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as err:
        logger.error(
            'action=reset_password_fail, email=\"{}\",'
            ' compromised_on=\"{}\", userid={},'
            ' message_id=\"{}\", error=\"{}\"'.format(email, sitecode, userid, message_id, err.message))
        return False
    else:
        status_code = r.status_code
        if status_code == 200:
            logger.info(
                'action=reset_password_success, email=\"{}\",'
                ' compromised_on=\"{}\", userid={},'
                ' message_id=\"{}\", status_code={}'.format(email, sitecode, userid, message_id, status_code))
            return True
        else:
            logger.error(
                'action=reset_password_fail, email=\"{}\",'
                ' compromised_on=\"{}\", userid={},'
                ' message_id=\"{}\", status_code={},'
                ' error=\"{}\"'.format(email, sitecode, userid, message_id, status_code, r.text))
            return False


def get_site1_guids(email, message_id):
    api_cert = config['site1']['api_cert']
    api_key = config['site1']['api_key']
    host = config['site1']['api_host']
    baseurl = config['site1']['accounts_baseurl']
    url = host + baseurl
    query = config['site1']['accounts_query'].format(quote_plus(email))
    headers = {'User-Agent': config['user_agent'],
               'SITE1-User-Credentials': 'get_guids_for_email:api_READER',
               'Content-Type': 'application/json'}
    try:
        r = requests.get(url, params=query, headers=headers, verify=False, cert=(api_cert, api_key))
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as err:
        logger.error('action=get_site1_guids_fail, email=\"{}\",'
                     ' message_id=\"{}\", error=\"{}\"'.format(email, message_id, err))
        return ['http exception']
    else:
        status_code = r.status_code
        if status_code == 200:
            response = json.loads(r.text)
            accounts = response['total']
            if accounts > 0:
                guids = list()
                valid_origin = re.compile('^SITE1$|^SITE2$|^SITE3$')
                for g in response['accounts']:
                    origin = g['account']['origin']['name']
                    if valid_origin.search(origin):
                        if 'category' in g['account']:
                            category = g['account']['category']['name']
                        else:
                            category = 'None'
                        guids.append({"guid": g['account']['@id'][16:],
                                      'category': category,
                                      'site': g['account']['origin']['name'] + '-' + g['account']['origin']['region'],
                                      'customer_id': g['account']['origin']['localId']})
                valid_accounts = len(guids)
                logger.info('action=get_site1_guids_success, email=\"{}\",'
                            ' message_id=\"{}\", accounts={}'.format(email, message_id, valid_accounts))
                return guids
            else:
                logger.warning('action=get_site1_guids_failure, email=\"{}\",'
                               ' message_id=\"{}\", error="No GUID found for user"'.format(email, message_id))
                return list()
        else:
            response = json.loads(r.text)
            logger.error('action=get_site1_guids_fail, email=\"{}\", error=\"{}\"'.format(email, response))
            return list()


def reset_site1_password(guid, email, compromised_on, site, category, customer_id, message_id):
    api_cert = config['site1']['api_cert']
    api_key = config['site1']['api_key']
    host = config['site1']['api_host']
    baseurl = config['site1']['passwords_baseurl']
    url = host + baseurl + guid
    headers = {'User-Agent': config['user_agent'],
               'SITE1-User-Credentials': 'reset-o-nator:api_READER,api_WRITER,api_PASSWORD_ACCESS',
               'Content-Type': 'application/json'}
    post_data = {'passwordHash': 'ALLOW-PASSWORD-RESET-VIA-ADMIN-TOOL'}
    try:
        res = requests.post(url, headers=headers, data=json.dumps(post_data),
                            verify=False, cert=(api_cert, api_key))
        # res.raise_for_status()
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as err:
        logger.error('action=reset_password_fail, email=\"{}\",'
                     ' compromised_on=\"{}\", guid=\"{}\", site=\"{}\",'
                     ' category=\"{}\", customer_id=\"{}\",'
                     ' message_id=\"{}\", error=\"{}\"'
                     .format(email, compromised_on, guid, site, category,
                             customer_id, message_id, err))
        return False
    else:
        if res.status_code == 200:
            logger.info('action=reset_password_success, email=\"{}\",'
                        ' compromised_on=\"{}\", guid=\"{}\", site=\"{}\",'
                        ' category=\"{}\", customer_id=\"{}\",'
                        ' message_id=\"{}\", status_code={}'
                        .format(email, compromised_on, guid, site, category,
                                customer_id, message_id, res.status_code))
            res.close()
            return True
        else:
            logger.error('action=reset_password_fail, email=\"{}\",'
                         ' compromised_on=\"{}\", guid=\"{}\", site=\"{}\",'
                         ' category=\"{}\", customer_id=\"{}\",'
                         ' message_id=\"{}\", status_code={}'
                         .format(email, compromised_on, guid, site, category,
                                 customer_id, message_id, res.status_code))
            res.close()
            return False


def process_site1_message(email, compromised_on, message_id):
    proc = 0
    guids = get_site1_guids(email, message_id)
    if 'http exception' not in guids:
        for g in guids:
            guid = g['guid']
            site = g['site']
            category = g['category']
            customer_id = g['customer_id']
            if reset_site1_password(guid, email, compromised_on, site, category, customer_id, message_id):
                proc += 1
        if proc >= 1:
            return True
        else:
            return False
    else:
        return False


def handle_messages(region, queue, aws_profile):
    session = boto3.Session(profile_name=aws_profile)
    sqs = session.client('sqs', region_name=region)
    url = sqs.get_queue_url(QueueName=queue)['QueueUrl']
    while True:
        messages = sqs.receive_message(QueueUrl=url, AttributeNames=['ApproximateReceiveCount'],
                                       MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=10)
        if 'Messages' in messages:
            for message in messages['Messages']:
                body = json.loads(message['Body'])
                message_id = message['MessageId']
                receipt_handle = message['ReceiptHandle']
                receive_count = int(message['Attributes']['ApproximateReceiveCount'])
                try:
                    m = json.loads(body['Message'])['message']
                    jmsg = json.loads(m)
                except ValueError as err:
                    logger.error('Malformed \"message\" field in SQS message,'
                                 ' unable to decode JSON. action=message_error,'
                                 ' message_id={}, error=\"{}\"'.format(message_id, err))
                else:
                    if route_message(jmsg, message_id):
                        logger.info('message_id={} processed OK, action=delete_from_queue'.format(message_id))
                        sqs.delete_message(QueueUrl=url, ReceiptHandle=receipt_handle)
                    else:
                        if receive_count >= 2:
                            logger.warning('Message message_id=\"{}\" failed to process'
                                           ' {} times, action=move_to_dlq'.format(message_id, receive_count))
        else:
            # logger.info('No new messages found')
            sleep(5)


class MyDaemon(Daemon):
    def run(self):
        aws_region = config['aws_region']
        profile = config['aws_profile']
        queue_name = config['queue_name']
        handle_messages(aws_region, queue_name, profile)


def main():
    daemon = MyDaemon(pidfile='/opt/reset-o-nator/reset-o-nator.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            print('Starting reset-o-nator daemon')
            logger.info('Starting reset-o-nator daemon, site2_api={}, site1_api={}'
                        .format(config['site2']['api_host'], config['site1']['api_host']))
            daemon.start()
        elif 'stop' == sys.argv[1]:
            print('Stopping reset-o-nator daemon')
            logger.info('Stopping reset-o-nator daemon')
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            print('Re-starting reset-o-nator daemon')
            logger.info('Re-starting reset-o-nator daemon, site2_api={}, site1_api={}'
                        .format(config['site2']['api_host'], config['site1']['api_host']))
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "\nusage: %s start|stop|restart\n" % sys.argv[0]
        sys.exit(2)


if __name__ == '__main__':
    main()
