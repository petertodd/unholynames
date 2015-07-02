#!/usr/bin/python3

import binascii
import dns.message
import dns.name
import dns.rdatatype
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.IN.AAAA
import dns.rrset
import jsonrpc
import re
import socket
import struct

import config

rpcproxy = jsonrpc.ServiceProxy(config.RPCURL)

def hexlify(b):
    return binascii.hexlify(b).decode('utf8')
def unhexlify(h):
    return binascii.unhexlify(h.encode('utf8'))

bitcoin_header_format = struct.Struct("<i 32s 32s I 4s I")
def serialize_block_header(block):
    """Serialize a block header from the RPC interface"""
    # Handle the genesis block
    if 'previousblockhash' not in block:
        block['previousblockhash'] = '00'*32

    return bitcoin_header_format.pack(
        block['version'],
        unhexlify(block['previousblockhash'])[::-1],
        unhexlify(block['merkleroot'])[::-1],
        block['time'],
        unhexlify(block['bits'])[::-1],
        block['nonce'])

def handle_AAAA_req(qs, resp):
    print('AAAA request for %r' % qs.name.to_text())
    if qs.name.to_text().endswith(config.BASE_NAME):
        req_name = qs.name.to_text()[0:-(len(config.BASE_NAME)+1)]

        # This is us, so responses are authorative
        resp.flags |= dns.flags.AA

        if re.match("^b[0-9]+-[0-4]$", req_name):
            req_name = req_name[1:]

            block_num, offset = req_name.split('-')
            block_num = int(block_num)
            offset = int(offset)

            print('Request for block %d, offset %d' % (block_num, offset))

            best_height = rpcproxy.getblockcount()

            if block_num > best_height:
                handle_missing_req(qs, resp)
            else:
                block = rpcproxy.getblockheader(rpcproxy.getblockhash(block_num))
                block_header = serialize_block_header(block)

                print('Header is %s' % hexlify(block_header))

                rdata = dns.rdata.from_wire(1, 28,
                        block_header[offset*16:(offset*16)+16],
                        0, 16)

                ttl = min((best_height - block_num)*600 + 30, # 10 minutes per block, min 30 seconds
                          60*60*24*14) # two weeks

                rrset = dns.rrset.from_rdata(qs.name, ttl, rdata)
                resp.answer.append(rrset)

                ns_name = dns.name.from_text(config.BASE_NAME)
                rrset = dns.rrset.from_text(ns_name, 1000,
                                            dns.rdataclass.IN,
                                            dns.rdatatype.NS,
                                            config.NS_NAME)
                resp.authority.append(rrset)
                print('resp %r' % resp)

        else:
            resp.set_rcode(dns.rcode.NXDOMAIN)
            handle_missing_req(qs, resp)

    else:
        # Unknown basename
        resp.set_rcode(dns.rcode.NXDOMAIN)

def handle_NS_req(qs, resp):
    print('NS request for %r' % qs.name.to_text())
    if qs.name.to_text().endswith(config.BASE_NAME):
        if qs.name.to_text() == config.BASE_NAME:
            req_name = qs.name.to_text()[0:-(len(config.BASE_NAME)+1)]

            # This is us, so responses are authorative
            resp.flags |= dns.flags.AA

            ns_name = dns.name.from_text(config.BASE_NAME)
            rrset = dns.rrset.from_text(ns_name, 1000,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.NS,
                                        config.NS_NAME)
            resp.answer.append(rrset)
            print('resp %r' % resp)
        else:
            handle_missing_req(qs, resp)
    else:
        # Didn't match
        resp.set_rcode(dns.rcode.NXDOMAIN)

def handle_SOA_req(qs, resp):
    print('A request for %r' % qs.name.to_text())
    if qs.name.to_text().endswith(config.BASE_NAME):
        # This is us, so responses are authorative
        resp.flags |= dns.flags.AA

        ns_name = dns.name.from_text(config.BASE_NAME)
        rrset = dns.rrset.from_text(qs.name, 1000,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SOA,
                                    '%s %s %d %d %d %d %d' % \
                                            (config.NS_NAME,
                                             'pete.petertodd.org.',
                                             2001020304,
                                             86400,
                                             7200,
                                             3600000,
                                             300))
        resp.answer.append(rrset)
        ns_name = dns.name.from_text(config.BASE_NAME)
        rrset = dns.rrset.from_text(ns_name, 1000,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.NS,
                                    config.NS_NAME)
        resp.authority.append(rrset)
        print('resp %r' % resp)
    else:
        # Didn't match
        resp.set_rcode(dns.rcode.NXDOMAIN)

def handle_missing_req(qs, resp):
    print('A request for %r' % qs.name.to_text())
    if qs.name.to_text().endswith(config.BASE_NAME):
        req_name = qs.name.to_text()[0:-(len(config.BASE_NAME)+1)]

        # This is us, so responses are authorative
        resp.flags |= dns.flags.AA

        # Didn't match
        #resp.set_rcode(dns.rcode.NXDOMAIN)

        ns_name = dns.name.from_text(config.BASE_NAME)
        rrset = dns.rrset.from_text(ns_name, 1000,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SOA,
                                    '%s %s %d %d %d %d %d' % \
                                            (config.NS_NAME,
                                             'pete.petertodd.org.',
                                             2001020304,
                                             86400,
                                             7200,
                                             3600000,
                                             300))
        resp.authority.append(rrset)
        print('resp %r' % resp)
    else:
        # Didn't match
        resp.set_rcode(dns.rcode.NXDOMAIN)

def requestHandler(sock, addr, wire_msg):
    msg = dns.message.from_wire(wire_msg)

    print('Query: %r %r %r %r' % (addr, wire_msg, msg, msg.opcode()))

    resp = dns.message.make_response(msg)

    # Default to not implemented
    #resp.set_rcode(dns.rcode.NOTIMP)

    if msg.opcode() == 0:
        # Limit to answering one question for now
        for qs in msg.question:
            #qs.name.to_text().endswith(config.BASE_NAME)
            print('qs.rdtype = %r qs.name = %r' % (dns.rdatatype.to_text(qs.rdtype),
                                                   qs.name.to_text()))
            if qs.name.to_text() == config.BASE_NAME:
                if qs.rdtype == dns.rdatatype.NS or qs.rdtype == dns.rdatatype.ANY:
                    handle_NS_req(qs, resp)
                elif qs.rdtype == dns.rdatatype.SOA:
                    handle_SOA_req(qs, resp)
                else:
                    handle_missing_req(qs, resp)

            else:
                if qs.rdtype == dns.rdatatype.AAAA or qs.rdtype == dns.rdatatype.ANY:
                    handle_AAAA_req(qs, resp)
                elif qs.rdtype == dns.rdatatype.NS:
                    handle_NS_req(qs, resp)
                elif qs.rdtype == dns.rdatatype.SOA:
                    handle_SOA_req(qs, resp)
                else:
                    handle_missing_req(qs, resp)

    print('resp is %r' % resp)
    if resp is not None:
        sock.sendto(resp.to_wire(), addr)

#    resp = None
#    try:
#        message_id = ord(message[0]) * 256 + ord(message[1])
#        print 'msg id = ' + str(message_id)
#        if message_id in serving_ids:
#            # the request is already taken, drop this message
#            print 'I am already serving this request.'
#            return
#        serving_ids.append(message_id)
#        try:
#            msg = dns.message.from_wire(message)
#            try:
#                op = msg.opcode()
#                if op == 0:
#                    # standard and inverse query
#                    qs = msg.question
#                    if len(qs) > 0:
#                        q = qs[0]
#                        print 'request is ' + str(q)
#                        if q.rdtype == dns.rdatatype.A:
#                            resp = std_qry(msg)
#                        else:
#                            # not implemented
#                            resp = self.make_response(qry=msg, RCODE=4)   # RCODE =  4    Not Implemented
#                else:
#                    # not implemented
#                    resp = self.make_response(qry=msg, RCODE=4)   # RCODE =  4    Not Implemented
#
#            except Exception, e:
#                print 'got ' + repr(e)
#                resp = self.make_response(qry=msg, RCODE=2)   # RCODE =  2    Server Error
#                print 'resp = ' + repr(resp.to_wire())
#
#        except Exception, e:
#            print 'got ' + repr(e)
#            resp = self.make_response(id=message_id, RCODE=1)   # RCODE =  1    Format Error
#            print 'resp = ' + repr(resp.to_wire())
#
#    except Exception, e:
#        # message was crap, not even the ID
#        print 'got ' + repr(e)
#
#    if resp:
#        s.sendto(resp.to_wire(), address)
#
#
#def std_qry(msg):
#    qs = msg.question
#    print str(len(qs)) + ' questions.'
#
#    answers = []
#    nxdomain = False
#    for q in qs:
#        qname = q.name.to_text()[:-1]
#        print 'q name = ' + qname
#
#        if qname.lower() == 'alice.com':
#            resp = make_response(qry=msg)
#            print 'returns: 1.2.3.4'
#            rrset = dns.rrset.from_text(q.name, 1000,
#                   dns.rdataclass.IN, dns.rdatatype.A, '1.2.3.4')
#            resp.answer.append(rrset)
#            print 'returns: 1.2.5.6'
#            rrset = dns.rrset.from_text(q.name, 1000,
#                   dns.rdataclass.IN, dns.rdatatype.A, '1.2.5.6')
#            resp.answer.append(rrset)
#            return resp
#        else:
#            return make_response(qry=msg, RCODE=3)   # RCODE =  3    Name Error
#
#
#def make_response(qry=None, id=None, RCODE=0):
#    if qry is None and id is None:
#        raise Exception, 'bad use of make_response'
#    if qry is None:
#        resp = dns.message.Message(id)
#        # QR = 1
#        resp.flags |= dns.flags.QR
#        if RCODE != 1:
#            raise Exception, 'bad use of make_response'
#    else:
#        resp = dns.message.make_response(qry)
#    resp.flags |= dns.flags.AA
#    resp.flags |= dns.flags.RA
#    resp.set_rcode(RCODE)
#    return resp


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', config.PORT))

while True:
    message, address = sock.recvfrom(1024)
    print('len(message) = %d' % len(message))
    requestHandler(sock, address, message)
