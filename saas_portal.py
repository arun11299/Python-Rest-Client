import os
import sys
import base64
import argparse
import cStringIO
import requests
from requests.auth import HTTPBasicAuth
import logging
from getpass import getpass

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

## Command line config item
cmd_args = dict()

## Logging configurations
LOG_FILE_NAME = "saas_portal_access.log"
LOG_SEVERITY  = {
                 'debug': logging.DEBUG,
                 'info' : logging.INFO
                }

log = logging.getLogger('logger')

init_uri = ""

def set_init_uri():
    global cmd_args, init_uri
    # We are always using 443 for now
    init_uri = "https://" + cmd_args['saas_host'] + ":443" + \
               "/api/akam/bo/v1/saas/vendors/1/platforms/O365/"
    return

URI_MAP = {
            'geodns-all': { 
                            'resource': 'geodns/',
                            'print': 'geodns_all_print'
                          },

            'geodns-regions': {
                                'resource': 'geodns/regions/',
                                'print': 'geodns_region_print',
                                'post_cb': 'gen_data_add_region'
                              },

            'geodns-mb-region': {
                                  'resource': 'geodns/regions/{0}/mailboxes/',
                                  'print': 'geodns_mb_region_print',
                                  'post_cb': 'gen_data_add_mbx' 
                                },

            'geodns-ip-region': {
                                  'resource': 'geodns/regions/{0}/ips/',
                                  'print': 'geodns_ip_region_print',
                                  'post_cb': 'gen_data_add_ips'
                                },

            'saas-hosts': {
                            'resource': 'appinfo/hosts/',
                            'print': 'saas_hosts_print',
                            'post_cb': 'gen_data_add_hosts'
                          },

          }

"""
    Python requests wrappers
"""

def geodns_all_print(xml, callback = False):
    tree = ET.ElementTree(ET.fromstring(xml))
    print "Mailbox to Region Mapping:"
    print "--------------------------"

    mbx_to_region_map = tree.find('mbx_to_region_map')
    for mbx_to_reg in mbx_to_region_map.getchildren():
        record = {'mbx_name': '', 'region_name': ''}

        for node in mbx_to_reg.getchildren():
            record[node.tag] = node.text

        print "{0:<10}{1}".format(record['mbx_name'], record['region_name'])

    print "\nRegion to IP Mapping:"
    print "-----------------------"

    region_to_ip_map = tree.find('region_to_ip_map')
    for region_to_ip in region_to_ip_map.getchildren():
        record = {'region_name': '', 'addresses':[]}

        for node in region_to_ip.getchildren():
            if node.tag == 'region_name':
                record[node.tag] = node.text
            else:
                for sub_node in node.getchildren():
                    record[node.tag].append(sub_node.text)

        print "{0}".format(record['region_name'])
        for address in record['addresses']:
            # I am sorry
            print "\t{0}".format(address)

    return

def geodns_region_print(xml, callback = False):
    tree = ET.ElementTree(ET.fromstring(xml))
    print "All regions:"
    print "------------"

    region_list = tree.find('regions')
    for region in region_list:
        if not callback:
            print region.text
        else:
            if callback(region.text):
                return True
    return


def geodns_mb_region_print(xml, callback = False):
    tree = ET.ElementTree(ET.fromstring(xml))

    print "Mailboxes for region:"
    print "---------------------"

    mbx_list = tree.find('mailboxes')
    for mbx in mbx_list:
        print mbx.text

    return

def geodns_ip_region_print(xml, callback = False):
    tree = ET.ElementTree(ET.fromstring(xml))

    print "IP Addresses for region:"
    print "------------------------"

    ip_list = tree.find('addresses')
    for ip in ip_list:
        print ip.text

    return

def saas_hosts_print(xml, callback = None):
    tree = ET.ElementTree(ET.fromstring(xml))

    print "Saas Hosts:"
    print "-----------"

    for hosts in tree.iter('saas_host'):
        record = {'id': '0', 'name': ''} 
        for host in hosts.getchildren():
            record[host.tag] = host.text
        print "{0}\t {1}".format(record['id'], record['name'])

def gen_data_add_region(regions = []):
    global log

    buffer = cStringIO.StringIO()
    buffer.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    buffer.write('<geodns>\n')

    for region in regions:
        buffer.write("<region>{0}</region>\n".format(region))

    buffer.write('</geodns>')

    content = buffer.getvalue()
    log.debug(content)
    buffer.close()

    return content


def gen_data_add_mbx(mbxs = []):
    global log

    buffer = cStringIO.StringIO()
    buffer.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    buffer.write('<geodns>\n')
    buffer.write('<mailboxes>\n')

    for mbx in mbxs:
        buffer.write("<mailbox>{0}</mailbox>".format(mbx))

    buffer.write('</mailboxes>\n')
    buffer.write('</geodns>\n')

    content = buffer.getvalue()
    log.debug(content)
    buffer.close()

    return content


def gen_data_add_ips(ips = []):
    global log

    buffer = cStringIO.StringIO()
    buffer.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    buffer.write('<geodns>\n')
    buffer.write('<addresses>\n')

    for ip in ips:
        buffer.write('<address>{0}</address>'.format(ip))

    buffer.write('</addresses>\n')
    buffer.write('</geodns>\n')

    content = buffer.getvalue()
    log.debug(content)
    buffer.close()

    return content


def gen_data_add_hosts(host = ''):
    global log

    buffer = cStringIO.StringIO()
    buffer.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    buffer.write('<saas_host>\n')
    buffer.write('<name>{0}</name>\n'.format(host))
    buffer.write('</saas_host>')

    content = buffer.getvalue()
    log.debug(content)
    buffer.close()

    return content


def make_get_req(resource = "", callback = "", post_cb = False):
    global cmd_args, init_uri, log

    headers = {'content-type': 'application/xml'}
    log.debug(init_uri + resource)

    r = requests.get(init_uri + resource, 
                     headers = headers,
                     auth = HTTPBasicAuth(cmd_args['user'], 
                                          cmd_args['password']),
                     verify = cmd_args['ssl_verify'])

    log.debug("Result code: {0}\n".format(r.status_code))
    log.debug(r.content + '\n')
    ret = globals()[callback](r.content, post_cb)

    if r.status_code != requests.codes.ok:
        log.error("Request failed for {0} with error code {1}\n".format(init_uri + resource, r.status_code))
        log.debug(str(r.headers) + '\n')
        sys.exit(1)


    return ret


def make_post_req(resource = "", data = ""):
    global cmd_args, init_uri, log

    headers = {'content-type': 'application/xml'}
    r = requests.post(init_uri + resource,
                      headers = headers,
                      auth = HTTPBasicAuth(cmd_args['user'],
                                           cmd_args['password']),
                      verify = cmd_args['ssl_verify'],
                      data = data)

    log.debug("Result code: {0}\n".format(r.status_code))

    if r.status_code != requests.codes.ok:
        log.error("Request failed for {0} with error code {1}\n".format(init_uri + resource, r.status_code))
        log.debug(str(r.headers) + '\n')
        sys.exit(1)

    return

def make_delete_req(resource = ""):
    global cmd_args, init_uri, log

    r = requests.delete(init_uri + resource,
                        auth = HTTPBasicAuth(cmd_args['user'],
                                           cmd_args['password']),
                        verify = cmd_args['ssl_verify'])
    log.debug("Result code: {0}\n".format(r.status_code))
    if r.status_code != requests.codes.ok:
        log.error("Request failed for {0} with error code {1}\n".format(init_uri + resource, r.status_code))
        log.debug(str(r.headers) + '\n')
        sys.exit(1)

    return


def process_cmd():
    "Process the command as per the cpommand line arguments"
    global cmd_args, URI_MAP, log
    # Identify whether its GET/POST
    if cmd_args['get_request']:
        req_type = "get_request"
    elif cmd_args['post_request']:
        req_type = "post_request"
    else:
        req_type = "delete_request"

    service = cmd_args[req_type]
    log.debug("Fetching resource for service {0}".format(service))

    if service:
        if service in ['geodns-mb-region', 'geodns-ip-region']: 
            if not cmd_args['req_region']:
                log.error("Region not provided for getting mailboxes")
                sys.exit(1)

            URI_MAP[service]['resource'] = \
                    (URI_MAP[service]['resource']).format(cmd_args['req_region'])
            pass

        if req_type == 'get_request':
            make_get_req(URI_MAP[service]['resource'], 
                         URI_MAP[service]['print'])

        if req_type == 'post_request':
            if service == 'saas-hosts':
                hosts_list = cmd_args['hosts_list']
                if not hosts_list:
                    return
                hosts_list = hosts_list.split(',')
                cb = URI_MAP['saas-hosts']['post_cb']
                for host in hosts_list:
                    data = globals()[cb](host)
                    make_post_req(URI_MAP['saas-hosts']['resource'],
                                  data)

            elif service == 'geodns-mbx-region':
                mbx_list = cmd_args['mbx_list']
                ip_list = cmd_args['ip_list']

                if mbx_list:
                    mbx_list = mbx_list.split(',')
                if ip_list:
                    ip_list = ip_list.split(',')

                region = cmd_args['req_region']

                # Check if region exists
                ret = make_get_req(URI_MAP['geodns-regions']['resource'],
                                   URI_MAP['geodns-regions']['print'],
                                   lambda x: True if x == region else False)

                if not ret:
                    ## Add region first, and then mailbox
                    cb = URI_MAP['geodns-regions']['post_cb']
                    data = globals()[cb]([region])
                    make_post_req(URI_MAP['geodns-regions']['resource'],
                                  data)
                if mbx_list:
                    cb = URI_MAP['geodns-mb-region']['post_cb']
                    data = globals()[cb](mbx_list)
                    make_post_req((URI_MAP['geodns-mb-region']['resource']).format(region),
                                  data)
                if ip_list:
                    cb = URI_MAP['geodns-ip-region']['post_cb']
                    data = globals()[cb](ip_list)
                    make_post_req((URI_MAP['geodns-ip-region']['resource']).format(region),
                                  data)

        if req_type == 'delete_request':
            if service == 'geodns-mbx-region':
                mbx_list = cmd_args['mbx_list']
                ip_list  = cmd_args['ip_list']
                region   = cmd_args['req_region']

                if not region:
                    return

                if (not mbx_list) and (not ip_list):
                    resource = URI_MAP['geodns-regions']['resource'] + region + '/'
                    make_delete_req(resource)
                    return

                if mbx_list:
                    mbx_list = mbx_list.split(',')
                    for mbx in mbx_list:
                        resource = (URI_MAP['geodns-mb-region']['resource']).format(region) + mbx + '/'
                        make_delete_req(resource)
                
                if ip_list:
                    ip_list = ip_list.split(',')
                    for ip in ip_list:
                        resource = (URI_MAP['geodns-ip-region']['resource']).format(region) + ip + '/'
                        make_delete_req(resource)

            elif service == 'saas-hosts':
                host_ids = cmd_args['host_ids']
                if not host_ids:
                    return

                host_ids = host_ids.split(',')
                for host_id in host_ids:
                    resource = URI_MAP['saas-hosts']['resource'] + host_id + '/'
                    make_delete_req(resource)
            pass
                    

    return

                    
"""
    Initial setup functions
"""
def parse_cmd_args():
    "Parse command line arguments and store them in config item"
    global cmd_args

    parser = argparse.ArgumentParser(description = "Saas data handler")
    parser.add_argument('-k', action = 'store_false', default = True,
                        dest = 'ssl_verify', 
                        help = "Ignore SSL certificate verification")

    parser.add_argument('-D', action = 'store', dest = 'log_level',
                        choices = ('debug', 'info'), default = 'info',
                        help = 'Logging level')

    parser.add_argument('--host', action = 'store', dest = 'saas_host',
                        help = 'Saas Portal host name', required = True)

    parser.add_argument('--get', choices = ('geodns-regions', 'geodns-all', 'geodns-mb-region', 
                                            'geodns-ip-region', 'saas-hosts'),
                        dest = 'get_request')

    parser.add_argument('--region', action = 'store', dest = 'req_region',
                        help = "Enter the region name for the mailboxes")

    parser.add_argument('--post', choices = ('geodns-mbx-region', 'saas-hosts'),
                        dest = 'post_request',
                        help = 'Use for adding single/multiple mailboxes to a region. \
                        Use --mbx-list to specify mailboxes and --region to specify the region')

    parser.add_argument('--mbx-list', action = 'store', dest = 'mbx_list',
                        help = 'List of mailboxes for a region. Use with --post/delete geodns-mbx-region')

    parser.add_argument('--ip-list', action = 'store', dest = 'ip_list',
                        help = 'List of IP addresses for a region. Use with --post/delete ')

    parser.add_argument('--hosts-list', action = 'store', dest = 'hosts_list',
                        help = 'List of Saas hosts. Use with --post/delete saas-hosts')

    parser.add_argument('--delete', choices = ('geodns-mbx-region', 'saas-hosts'),
                        dest = 'delete_request',
                        help = 'Use for deleting mail boxes/regions/ip')

    parser.add_argument('--host-ids', action = 'store', dest = 'host_ids',
                        help = 'List of host ids which needs to be deleted. Use with --delete saas-hosts')

    parser.add_argument('--user', action="store", dest = 'user', required = True,
                        help = 'User name for authentication')

    parser.add_argument('--reuse-passwd', action = 'store_true', dest = 'reuse_passwd',
                        default = False,
                        help = 'Reuses the password used last time')

    cmd_args = vars(parser.parse_args())

    # What a stupid place to be
    setup_logger()

    if not validate_cmd_args():
        parser.print_help()
        sys.exit(1)


def validate_cmd_args():
    "Validate the passed command line arguments"
    global cmd_args, log

    log.info(str(cmd_args))
    # Check '--mailbox' option is provided when --get is geodns-mb-region
    # option
    if cmd_args['get_request'] == 'geodns-mb-region':
        if not cmd_args['req_region']:
            return False

    if cmd_args['post_request'] == 'geodns-mbx-region':
        if cmd_args['mbx_list'] or cmd_args['ip_list']:
            if not cmd_args['req_region']:
                return False
    return True

def ask_for_password():
    global cmd_args, log

    if cmd_args['reuse_passwd']:
        if not os.path.exists(".portal_password.b64"):
            print "Error: Password file not found"
        else:
            fd = open(".portal_password.b64", 'rb')
            enc_password = fd.readline().rstrip()
            fd.close()
            cmd_args['password'] = base64.b64decode(enc_password)
            return

    cmd_args['password'] = getpass()
    # create a hidden file to store the password in base64
    # encoding. Done for reuse option 
    fd = open(".portal_password.b64", 'wb')
    enc_passwd = base64.b64encode(cmd_args['password'])
    fd.write(enc_passwd)
    fd.close()
    return

def setup_logger():
    global cmd_args, log

    log_level = LOG_SEVERITY[cmd_args['log_level']]

    logging.basicConfig(filename = LOG_FILE_NAME, 
                           level = log_level)

    log.setLevel(log_level)

    fh = logging.FileHandler(LOG_FILE_NAME)
    fh.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)

    log.addHandler(fh)
    return


if __name__ == "__main__":
    parse_cmd_args()
    ask_for_password()

    set_init_uri()
    process_cmd()
