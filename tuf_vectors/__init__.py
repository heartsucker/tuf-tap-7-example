# -*- coding: utf-8 -*-

import base64
import binascii
import ed25519
import hashlib
import json
import os

from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from os import path
from securesystemslib.formats import encode_canonical as olpc_cjson


PINNED_VERSION = 1


def load_test_vectors(key_type,
                      signature_scheme,
                      signature_encoding,
                      compact,
                      cjson_strategy):
    base_path = path.join(path.dirname(path.abspath(__file__)), '..', 'vectors')
    vectors = {}

    for vector_path in os.listdir(base_path):
        with open(path.join(base_path, vector_path)) as f:
            vector = json.loads(f.read())
            assert vector['version'] == PINNED_VERSION

            vectors[vector_path.replace('.json', '')] = \
                Vector(steps=vector['steps'], key_type=key_type,
                       signature_scheme=signature_scheme,
                       signature_encoding=signature_encoding,
                       compact=compact,
                       cjson_strategy=cjson_strategy)

    return vectors


def short_key_type(typ) -> str:
    if typ == 'ed25519':
        return 'ed25519'
    elif typ.startswith('rsa'):
        return 'rsa'
    else:  # pragma: no cover
        raise Exception('Unknown key typ: {}'.format(typ))


def sha256(data, bad_hash: bool) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hashlib.sha256()
    h.update(data)
    d = h.digest()

    if bad_hash:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def sha512(data, bad_hash: bool) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hashlib.sha512()
    h.update(data)
    d = h.digest()

    if bad_hash:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


class Vector:

    def __init__(self, steps, key_type,
                 signature_scheme,
                 signature_encoding,
                 compact,
                 cjson_strategy):
        self.compact = compact

        self.steps = []
        for step in steps:
            step = Step(step,
                        key_type=key_type,
                        signature_scheme=signature_scheme,
                        signature_encoding=signature_encoding,
                        compact=compact,
                        cjson_strategy=cjson_strategy)
            self.steps.append(step)

    def jsonify(self, jsn):
        kwargs = {'sort_keys': True, }

        if not self.compact:
            kwargs['indent'] = 2
        else:
            kwargs['separators'] = (',', ':')

        out = json.dumps(jsn, **kwargs)

        if not self.compact:
            out += '\n'

        return out


def _cjson_subset_check(jsn):
    if isinstance(jsn, list):
        for j in jsn:
            _cjson_subset_check(j)
    elif isinstance(jsn, dict):
        for _, v in jsn.items():
            _cjson_subset_check(v)
    elif isinstance(jsn, str):
        pass
    elif isinstance(jsn, bool):
        pass
    elif jsn is None:
        pass
    elif isinstance(jsn, int):
        pass
    elif isinstance(jsn, float):  # pragma: no cover
        raise ValueError('CJSON does not allow floats')
    else:  # pragma: no cover
        raise ValueError('What sort of type is this? {} {}'.format(type(jsn), jsn))


class Step:

    def __init__(self, step_data, key_type,
                 signature_scheme,
                 signature_encoding,
                 compact,
                 cjson_strategy):
        self.key_store = {}
        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy

        self.root_version = step_data['meta']['root']['signed']['version']
        self.snapshot_version = step_data['meta']['snapshot']['signed']['version']
        self.targets_version = step_data['meta']['targets']['signed']['version']
        self.timestamp_version = step_data['meta']['timestamp']['signed']['version']

        self.root_expired = step_data['meta']['root']['signed']['expired']
        self.snapshot_expired = step_data['meta']['snapshot']['signed']['expired']
        self.targets_expired = step_data['meta']['targets']['signed']['expired']
        self.timestamp_expired = step_data['meta']['timestamp']['signed']['expired']

        self.root_keys = [x['key_index']
                          for x in step_data['meta']['root']['signed']['roles']['root']['keys']]
        self.snapshot_keys = [x['key_index'] for x in step_data[
            'meta']['root']['signed']['roles']['snapshot']['keys']]
        self.targets_keys = [x['key_index']
                             for x in step_data['meta']['root']['signed']['roles']['targets']['keys']]
        self.timestamp_keys = [x['key_index'] for x in step_data[
            'meta']['root']['signed']['roles']['timestamp']['keys']]

        self.root_threshold = step_data['meta']['root']['signed']['roles']['root']['threshold']
        self.snapshot_threshold = step_data['meta']['root'][
            'signed']['roles']['snapshot']['threshold']
        self.targets_threshold = step_data['meta']['root'][
            'signed']['roles']['targets']['threshold']
        self.timestamp_threshold = step_data['meta']['root'][
            'signed']['roles']['timestamp']['threshold']

        self.root_sign = [(x['key_index'], x['bad_signature'])
                          for x in step_data['meta']['root']['signatures']]
        self.snapshot_sign = [(x['key_index'], x['bad_signature'])
                              for x in step_data['meta']['snapshot']['signatures']]
        self.targets_sign = [(x['key_index'], x['bad_signature'])
                             for x in step_data['meta']['targets']['signatures']]
        self.timestamp_sign = [(x['key_index'], x['bad_signature'])
                               for x in step_data['meta']['timestamp']['signatures']]

        self.top_level_keys = [(x['key_index'], x['bad_id'])
                               for x in step_data['meta']['root']['signed']['keys']]
        self.targets = [(x, b'wat wat wat')
                        for x in step_data['meta']['targets']['signed']['targets'].keys()]

        self.generate_root()
        self.generate_targets()
        self.generate_snapshot()
        self.generate_timestamp()

        self.step_meta = {
            'update': step_data['update'],
            'targets': step_data['targets'],
        }

    def key_id(self, pub: str, bad_id: bool) -> str:
        return sha256(self.cjson(pub).encode('utf-8'), bad_id)

    def cjson(self, jsn) -> str:
        if self.cjson_strategy == 'olpc':
            return olpc_cjson(jsn)
        elif self.cjson_strategy == 'json-subset':
            _cjson_subset_check(jsn)
            return json.dumps(jsn, sort_keys=True, separators=(',', ':'))
        else:
            raise ValueError('{} is not a valid CJSON strategy'.format(self.cjson_strategy))

    def jsonify(self, jsn):
        kwargs = {'sort_keys': True, }

        if not self.compact:
            kwargs['indent'] = 2
        else:
            kwargs['separators'] = (',', ':')

        out = json.dumps(jsn, **kwargs)

        if not self.compact:
            out += '\n'

        return out

    def encode_signature(self, sig) -> str:
        if self.signature_encoding == 'hex':
            return binascii.hexlify(sig).decode('utf-8')
        elif self.signature_encoding == 'base64':
            return base64.b64encode(sig).decode('utf-8')
        else:  # pragma: no cover
            raise ValueError('Invalid signature encoding: {}'.format(self.signature_encoding))

    def get_key(self, key_idx) -> (str, str, str):
        try:
            (priv, pub) = self.key_store[key_idx]
        except KeyError:
            path_base = path.join(path.dirname(__file__), '..', 'keys',
                                  '{}-{}.'.format(self.key_type, key_idx))
            with open('{}priv'.format(path_base)) as f:
                priv = f.read()

            with open('{}pub'.format(path_base)) as f:
                pub = f.read()

            self.key_store[key_idx] = (priv, pub)

        return (priv, pub)

    def sign(self, sig_directives, signed) -> list:
        data = self.cjson(signed).encode('utf-8')

        sigs = []
        for (priv, pub), bad_sig in sig_directives:
            if self.signature_scheme == 'ed25519':
                priv = ed25519.SigningKey(binascii.unhexlify(priv))
                sig = priv.sign(data)
            elif self.signature_scheme.startswith('rsa'):
                if self.signature_scheme == 'rsassa-pss-sha256':
                    h = SHA256.new(data)
                elif self.signature_scheme == 'rsassa-pss-sha512':
                    h = SHA512.new(data)
                else:
                    raise Exception('Unknown signature scheme: {}'.format(self.signature_scheme))

                rsa = RSA.importKey(priv)
                signer = PKCS1_PSS.new(rsa)
                sig = signer.sign(h)
            else:
                raise Exception('Unknow signature scheme: {}'.format(self.signature_scheme))

            if bad_sig:
                sig[0] ^= 0x01

            sig_data = {
                'keyid': self.key_id(pub, bad_id=False),
                'method': self.signature_scheme,
                'sig': self.encode_signature(sig),
            }
            sigs.append(sig_data)

        return sigs

    def generate_root(self) -> None:
        signed = {
            '_type': 'Root',
            'version': self.root_version,
            'consistent_snapshot': False,
            'expires': '2017-01-01T00:00:00Z' if self.root_expired else '2038-01-19T03:14:06Z',
            'keys': {},
            'roles': {
                'root': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.root_keys],
                    'threshold': self.root_threshold,
                },
                'targets': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.targets_keys],
                    'threshold': self.targets_threshold,
                },
                'timestamp': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.timestamp_keys],
                    'threshold': self.timestamp_threshold,
                },
                'snapshot': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.snapshot_keys],
                    'threshold': self.snapshot_threshold,
                },
            }
        }

        for key_idx, bad in self.top_level_keys:
            _, pub = self.get_key(key_idx)
            signed['keys'][self.key_id(pub, bad_id=bad)] = {
                'keytype': short_key_type(self.key_type),
                'keyval': {
                    'public': pub
                },
            }

        sig_directives = [(self.get_key(key_idx), bad) for (key_idx, bad) in self.root_sign]
        self.root = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_targets(self) -> None:
        signed = {
            '_type': 'Targets',
            'version': self.targets_version,
            'expires': '2017-01-01T00:00:00Z' if self.targets_expired else '2038-01-19T03:14:06Z',
            'targets': {},
        }

        for target, content in self.targets:
            # TODO uptane custom
            meta = {
                'length': len(content),
                'hashes': {
                    'sha256': sha256(content, bad_hash=False),
                    'sha512': sha512(content, bad_hash=False),
                }
            }

            signed['targets'][target] = meta

        sig_directives = [(self.get_key(key_idx), bad) for (key_idx, bad) in self.targets_sign]
        self.targets = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_snapshot(self) -> None:
        root_json = self.jsonify(self.root)

        signed = {
            '_type': 'Snapshot',
            'version': self.snapshot_version,
            'expires': '2017-01-01T00:00:00Z' if self.snapshot_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'root.json': {
                    'version': self.root_version,
                    'length': len(root_json),
                    'hashes': {
                        'sha256': sha256(root_json, bad_hash=False),
                        'sha512': sha512(root_json, bad_hash=False),
                    },
                },
                'targets.json': {
                    'version': self.targets_version,
                },
            },
        }

        sig_directives = [(self.get_key(key_idx), bad) for (key_idx, bad) in self.snapshot_sign]
        self.snapshot = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_timestamp(self) -> None:
        snapshot_json = self.jsonify(self.snapshot)

        signed = {
            '_type': 'Timestamp',
            'version': self.timestamp_version,
            'expires': '2017-01-01T00:00:00Z' if self.timestamp_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'snapshot.json': {
                    'version': self.snapshot_version,
                    'length': len(snapshot_json),
                    'hashes': {
                        'sha256': sha256(snapshot_json, bad_hash=False),
                        'sha512': sha512(snapshot_json, bad_hash=False),
                    },
                },
            },
        }

        sig_directives = [(self.get_key(key_idx), bad) for (key_idx, bad) in self.timestamp_sign]
        self.timestamp = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}
