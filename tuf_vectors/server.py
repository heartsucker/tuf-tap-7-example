# -*- coding: utf-8 -*-

import json

from flask import Flask, Response, abort, make_response
from functools import wraps
from os import path
from tuf_vectors import load_test_vectors


def json_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        resp.headers['Content-Type'] = 'application/json'
        return resp
    return decorated_function


def init_app(
        key_type,
        signature_scheme,
        signature_encoding,
        compact,
        cjson_strategy):
    app = Flask(__name__, static_folder=None, template_folder=None)

    counter = {}
    repos = load_test_vectors(key_type=key_type,
                              signature_scheme=signature_scheme,
                              signature_encoding=signature_encoding,
                              compact=compact, cjson_strategy=cjson_strategy)

    @app.route('/')
    @json_response
    def index():
        return json.dumps(list(repos.keys()))

    @app.route('/<string:repo>/reset', methods=['POST'])
    def reset(repo):
        try:
            counter.pop(repo, None)
        except KeyError as e:
            app.logger.warn(e)
            pass
        return '', 204

    @app.route('/<string:repo>/step', methods=['POST'])
    @json_response
    def step(repo):
        current = counter.get(repo, 0)
        counter[repo] = current + 1
        try:
            step_meta = repos[repo].steps[current].step_meta
        except KeyError as e:
            app.logger.warn(e)
            abort(400)
        except IndexError as e:
            app.logger.warn(e)
            return '', 204

        # TODO if current step == 0, include root keys for pinning
        return json.dumps({
            'update': step_meta['update'],
            'targets': step_meta['targets'],
        })

    @app.route('/<string:repo>/<int:root_version>.root.json')
    @json_response
    def root(repo, root_version):
        current = counter.get(repo)
        if current is None:
            abort(400)

        root_idx = root_version - 1
        if current >= root_idx:
            try:
                if current > len(repos[repo].steps):
                    abort(400)
                repo = repos[repo]
                return repo.jsonify(repo.steps[root_idx].root)
            except (IndexError, KeyError) as e:
                app.logger.warn(e)
                abort(400)
        else:
            return abort(404)

    @app.route('/<string:repo>/<string:metadata>.json')
    @json_response
    def meta(repo, metadata):
        current = counter.get(repo)
        if current is None:
            abort(400)

        if metadata not in ['root', 'timestamp', 'targets', 'snapshot']:
            abort(404)

        try:
            repo = repos[repo]
            return repo.jsonify(getattr(repo.steps[current - 1], metadata))
        except (IndexError, KeyError) as e:
            app.logger.warn(e)
            abort(400)
        except AttributeError as e:
            app.logger.warn(e)
            abort(404)

    @app.route('/<string:repo>/<path:content_path>')
    def repo(repo, content_path):
        try:
            current = counter[repo]
            repo = repos[repo].steps[current - 1]
        except (IndexError, KeyError) as e:
            app.logger.warn(e)
            abort(400)

        for target in repo.TARGETS:
            if target[0] == content_path:
                return target[1]

        abort(404)

    return app
