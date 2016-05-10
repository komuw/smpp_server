# -*- coding: utf-8 -*-
import unittest
import collections
from datetime import datetime, timedelta

from smpp.esme import ESME
from smpp.clickatell import clickatell_defaults
from smpp import pdu
from smpp.pdu_builder import SubmitSM
import credentials_test
try:
    import credentials_priv
except:
    pass
import binascii
import re
try:
    import json
except:
    import simplejson as json

from test.pdu import pdu_objects
from test.pdu_hex import pdu_hex_strings
from test import pdu_asserts
from test import pdu_hex_asserts


def unpack_hex(pdu_hex):
    """Unpack PDU hex string and return it as a dictionary"""
    return pdu.unpack_pdu(binascii.a2b_hex(hexclean(pdu_hex)))


def hexclean(dirtyhex):
    """Remove whitespace, comments & newlines from hex string"""
    return re.sub(r'\s', '', re.sub(r'#.*\n', '\n', dirtyhex))


def prettydump(pdu_obj):
    """Unpack PDU dictionary and dump it as a JSON formatted string"""
    return json.dumps(pdu_obj, indent=4, sort_keys=True)


def hex_to_named(dictionary):
    """
    Recursive function to convert values in test dictionaries to
    their named counterparts that unpack_pdu returns
    """
    clone = dictionary.copy()
    for key, value in clone.items():
        if isinstance(value, collections.Mapping):
            clone[key] = hex_to_named(value)
        else:
            lookup_table = pdu.maps.get('%s_by_hex' % key)
            if lookup_table:
                # overwrite with mapped value or keep using
                # default if the dictionary key doesn't exist
                clone[key] = lookup_table.get("%.2d" % value, value)
    return clone


def create_pdu_asserts():
    pdu_index = 0
    for pdu_object in pdu_objects:
        pdu_index += 1
        pstr = "\n########################################\n"
        pstr += "pdu_json_"
        pstr += ('%010d' % pdu_index)
        pstr += " = '''"
        pstr += prettydump(pdu.unpack_pdu(pdu.pack_pdu(pdu_object)))
        pstr += "'''"
        print pstr


def create_pdu_hex_asserts():
    pdu_index = 0
    for pdu_hex in pdu_hex_strings:
        pdu_index += 1
        pstr = "\n########################################\n"
        pstr += "pdu_json_"
        pstr += ('%010d' % pdu_index)
        pstr += " = '''"
        pstr += prettydump(pdu.unpack_hex(pdu_hex))
        pstr += "'''"
        print pstr


# # :w|!python % > test/pdu_asserts.py
# create_pdu_asserts()
# quit()

# # :w|!python % > test/pdu_hex_asserts.py
# create_pdu_hex_asserts()
# quit()


class PduTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def assertDictEquals(self, dictionary1, dictionary2, depth=[]):
        """
        Recursive dictionary comparison, will fail if any keys and values
        in the two dictionaries don't match. Displays the key chain / depth
        and which parts of the two dictionaries didn't match.
        """
        d1_keys = dictionary1.keys()
        d1_keys.sort()

        d2_keys = dictionary2.keys()
        d2_keys.sort()

        self.failUnlessEqual(d1_keys, d2_keys,
            "Dictionary keys do not match, %s vs %s" % (
                d1_keys, d2_keys))
        for key, value in dictionary1.items():
            if isinstance(value, collections.Mapping):
                # go recursive
                depth.append(key)
                self.assertDictEquals(value, dictionary2[key], depth)
            else:
                self.failUnlessEqual(value, dictionary2[key],
                    "Dictionary values do not match for key '%s' "
                    "(%s vs %s) at depth: %s.\nDictionary 1: %s\n"
                    "Dictionary 2: %s\n" % (
                        key, value, dictionary2[key], ".".join(depth),
                        prettydump(dictionary1), prettydump(dictionary2)))

    def test_pack_unpack_pdu_objects(self):
        print ''
        """
        Take a dictionary, pack and unpack it and dump it as JSON correctly
        """
        pdu_index = 0
        for pdu_object in pdu_objects:
            pdu_index += 1
            padded_index = '%010d' % pdu_index
            print '...', padded_index
            str_eval = re.sub('null', 'None', getattr(pdu_asserts, 'pdu_json_' + padded_index))
            self.assertEquals(
                pdu.unpack_pdu(pdu.pack_pdu(pdu_object)),
                eval(str_eval)
            )

    def test_pack_unpack_pdu_hex_strings(self):
        print ''
        """
        Read the hex data, clean it, and unpack it to JSON correctly
        """
        pdu_index = 0
        for pdu_hex in pdu_hex_strings:
            pdu_index += 1
            padded_index = '%010d' % pdu_index
            print '...', padded_index
            str_eval = re.sub('null', 'None', eval('pdu_hex_asserts.pdu_json_' + padded_index))
            self.assertEquals(
                unpack_hex(pdu_hex),
                eval(str_eval)
            )

    def test_pack_unpack_performance(self):
        import platform
        if platform.python_implementation() == "PyPy":
            # Skip this test on pypy, because the JIT warmup time dominates.
            return
        print ''
        """
        Pack & unpack 500 submit_sm PDUs in under 1 second
        """
        submit_sm = {
            'header': {
                'command_length': 0,
                'command_id': 'submit_sm',
                'command_status': 'ESME_ROK',
                'sequence_number': 0,
            },
            'body': {
                'mandatory_parameters': {
                    'service_type': '',
                    'source_addr_ton': 1,
                    'source_addr_npi': 1,
                    'source_addr': '',
                    'dest_addr_ton': 1,
                    'dest_addr_npi': 1,
                    'destination_addr': '',
                    'esm_class': 0,
                    'protocol_id': 0,
                    'priority_flag': 0,
                    'schedule_delivery_time': '',
                    'validity_period': '',
                    'registered_delivery': 0,
                    'replace_if_present_flag': 0,
                    'data_coding': 0,
                    'sm_default_msg_id': 0,
                    'sm_length': 1,
                    'short_message': '',
                },
            },
        }
        start = datetime.now()
        for x in range(500):
            x += 1
            submit_sm['header']['sequence_number'] = x
            sm = 'testing: x = '+str(x)+''
            submit_sm['body']['mandatory_parameters']['short_message'] = sm
            u = pdu.unpack_pdu(pdu.pack_pdu(submit_sm))
        delta = datetime.now() - start
        print '... 500 pack & unpacks in:', delta
        self.assertTrue(delta < timedelta(seconds=1))

    def test_pack_unpack_of_unicode(self):
        """
        SMPP module should be able to pack & unpack unicode characters
        without a problem
        """
        submit_sm = {
            'header': {
                'command_length': 67,
                'command_id': 'submit_sm',
                'command_status': 'ESME_ROK',
                'sequence_number': 0,
            },
            'body': {
                'mandatory_parameters': {
                    'service_type': '',
                    'source_addr_ton': 'international',
                    'source_addr_npi': 'unknown',
                    'source_addr': '',
                    'dest_addr_ton': 'international',
                    'dest_addr_npi': 'unknown',
                    'destination_addr': '',
                    'esm_class': 0,
                    'protocol_id': 0,
                    'priority_flag': 0,
                    'schedule_delivery_time': '',
                    'validity_period': '',
                    'registered_delivery': 0,
                    'replace_if_present_flag': 0,
                    'data_coding': 0,
                    'sm_default_msg_id': 0,
                    'sm_length': 34,
                    'short_message': u'Vumi says: أبن الشرموطة'.encode('utf-8'),
                },
            },
        }
        self.assertDictEquals(
            hex_to_named(submit_sm),
            pdu.unpack_pdu(pdu.pack_pdu(submit_sm))
        )

    def test_pack_unpack_of_ascii_and_unicode_8_16_32(self):
        """
        SMPP module should be able to pack & unpack unicode characters
        without a problem
        """
        submit_sm = {
            'header': {
                'command_length': 65,
                'command_id': 'submit_sm',
                'command_status': 'ESME_ROK',
                'sequence_number': 0,
            },
            'body': {
                'mandatory_parameters': {
                    'service_type': '',
                    'source_addr_ton': 'international',
                    'source_addr_npi': 'unknown',
                    'source_addr': '',
                    'dest_addr_ton': 'international',
                    'dest_addr_npi': 'unknown',
                    'destination_addr': '',
                    'esm_class': 0,
                    'protocol_id': 0,
                    'priority_flag': 0,
                    'schedule_delivery_time': '',
                    'validity_period': '',
                    'registered_delivery': 0,
                    'replace_if_present_flag': 0,
                    'data_coding': 0,
                    'sm_default_msg_id': 0,
                    'sm_length': 32,
                    'short_message': u'a \xf0\x20\u0373\u0020\u0433\u0020\u0533\u0020\u05f3\u0020\u0633\u0020\u13a3\u0020\u16a3 \U0001f090'.encode('utf-8'),
                },
            },
        }
        self.assertDictEquals(
            hex_to_named(submit_sm),
            pdu.unpack_pdu(pdu.pack_pdu(submit_sm))
        )

    def test_optional_param_length(self):
        # Variable length hex string.
        self.assertEqual(
            '04240000', pdu.encode_optional_parameter('message_payload', ''))
        self.assertEqual(
            '04240004deadbeef',
            pdu.encode_optional_parameter('message_payload', 'deadbeef'))

        # Fixed length integer.
        self.assertEqual(
            '020400020000',
            pdu.encode_optional_parameter('user_message_reference', 0))
        self.assertEqual(
            '0204000201ff',
            pdu.encode_optional_parameter('user_message_reference', 511))

    def test_encode_param_type_no_value(self):
        self.assertEqual(pdu.encode_param_type(None, 'integer'), None)
        self.assertEqual(pdu.encode_param_type(None, 'string'), None)
        self.assertEqual(pdu.encode_param_type(None, 'xstring'), None)
        self.assertEqual(pdu.encode_param_type(None, 'bitmask'), None)
        self.assertEqual(pdu.encode_param_type(None, 'hex'), None)

    def test_encode_param_type_integer(self):
        self.assertEqual(pdu.encode_param_type(0, 'integer'), '00')
        self.assertEqual(pdu.encode_param_type(1, 'integer'), '01')
        self.assertEqual(pdu.encode_param_type(255, 'integer'), 'ff')
        self.assertEqual(pdu.encode_param_type(256, 'integer'), '0100')

        self.assertEqual(pdu.encode_param_type(0, 'integer', min=2), '0000')
        self.assertEqual(pdu.encode_param_type(255, 'integer', min=2), '00ff')
        self.assertEqual(pdu.encode_param_type(256, 'integer', min=2), '0100')

        self.assertEqual(pdu.encode_param_type(255, 'integer', max=1), 'ff')
        self.assertRaises(ValueError, pdu.encode_param_type, 256, 'integer', max=1)

    def test_encode_param_type_string(self):
        self.assertEqual(pdu.encode_param_type('', 'string'), '00')
        self.assertEqual(pdu.encode_param_type('ABC', 'string'), '41424300')
        self.assertEqual(pdu.encode_param_type('ABC', 'string', max=4), '41424300')
        self.assertRaises(
            ValueError, pdu.encode_param_type, 'ABC', 'string', max=3)

    def test_encode_param_type_xstring(self):
        self.assertEqual(pdu.encode_param_type('', 'xstring'), '')
        self.assertEqual(pdu.encode_param_type('ABC', 'xstring'), '414243')
        self.assertEqual(pdu.encode_param_type('ABC', 'xstring', max=3), '414243')
        self.assertRaises(
            ValueError, pdu.encode_param_type, 'ABC', 'xstring', max=2)

    def test_ignore_invalid_null_after_short_message_field(self):
        """
        At least one provider sends us an invalid deliver_sm PDU with a null
        byte after the short_message field.
        """
        deliver_sm = {
            'header': {
                'command_length': 0,
                'command_id': 'deliver_sm',
                'command_status': 'ESME_ROK',
                'sequence_number': 0,
            },
            'body': {
                'mandatory_parameters': {
                    'service_type': '',
                    'source_addr_ton': 1,
                    'source_addr_npi': 1,
                    'source_addr': '',
                    'dest_addr_ton': 1,
                    'dest_addr_npi': 1,
                    'destination_addr': '',
                    'esm_class': 0,
                    'protocol_id': 0,
                    'priority_flag': 0,
                    'schedule_delivery_time': '',
                    'validity_period': '',
                    'registered_delivery': 0,
                    'replace_if_present_flag': 0,
                    'data_coding': 0,
                    'sm_default_msg_id': 0,
                    'sm_length': 1,
                    'short_message': 'test',
                },
            },
        }
        packed_pdu = pdu.pack_pdu(deliver_sm)
        unpacked_pdu = pdu.unpack_pdu(packed_pdu)
        unpacked_dodgy_pdu = pdu.unpack_pdu(packed_pdu + '\x00')
        self.assertEqual(unpacked_pdu, unpacked_dodgy_pdu)

    def test_validity_period(self):
        """
        Should be able to pack and unpack a PDU with a valid validity_period.
        """
        submit_sm = {
            'header': {
                'command_length': 67,
                'command_id': 'submit_sm',
                'command_status': 'ESME_ROK',
                'sequence_number': 0,
            },
            'body': {
                'mandatory_parameters': {
                    'service_type': '',
                    'source_addr_ton': 'international',
                    'source_addr_npi': 'unknown',
                    'source_addr': '',
                    'dest_addr_ton': 'international',
                    'dest_addr_npi': 'unknown',
                    'destination_addr': '',
                    'esm_class': 0,
                    'protocol_id': 0,
                    'priority_flag': 0,
                    'schedule_delivery_time': '',
                    'validity_period': '000001234567800R',
                    'registered_delivery': 0,
                    'replace_if_present_flag': 0,
                    'data_coding': 0,
                    'sm_default_msg_id': 0,
                    'sm_length': 18,
                    'short_message': 'Test Short Message',
                },
            },
        }
        self.assertEqual(pdu.unpack_pdu(pdu.pack_pdu(submit_sm)), submit_sm)


class PduBuilderTestCase(unittest.TestCase):
    def test_submit_sm_message_too_long(self):
        short_message = '1234567890' * 26
        submit_sm = SubmitSM(5, short_message=short_message)
        self.assertRaises(ValueError, submit_sm.get_hex)


if __name__ == '__main__':
    print '\n##########################################################\n'
    # deliv_sm_resp = DeliverSMResp(23)
    # print deliv_sm_resp.get_obj()
    # print deliv_sm_resp.get_hex()
    # enq_lnk = EnquireLink(7)
    # print enq_lnk.get_obj()
    # print enq_lnk.get_hex()
    # sub_sm = SubmitSM(5, short_message='testing testing')
    # print sub_sm.get_obj()
    # print sub_sm.get_hex()
    # sub_sm.add_message_payload('01020304')
    # print sub_sm.get_obj()
    # print sub_sm.get_hex()
    # print unpack_pdu(sub_sm.get_bin())
    print '\n##########################################################\n'

    esme = ESME()
    esme.loadDefaults(clickatell_defaults)
    esme.loadDefaults(credentials_test.logica)
    print esme.defaults
    esme.bind_transmitter()
    print esme.state
    start = datetime.now()
    for x in range(1):
        esme.submit_sm(
                short_message='gobbledygook',
                destination_addr='555',
                )
        print esme.state
    for x in range(1):
        esme.submit_multi(
                short_message='gobbledygook',
                dest_address=['444', '333'],
                )
        print esme.state
    for x in range(1):
        esme.submit_multi(
                short_message='gobbledygook',
                dest_address=[
                    {'dest_flag': 1, 'destination_addr': '111'},
                    {'dest_flag': 2, 'dl_name': 'list22222'},
                    ],
                )
        print esme.state
    delta = datetime.now() - start
    esme.disconnect()
    print esme.state
    print 'excluding binding ... time to send messages =', delta
