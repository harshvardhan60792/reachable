"""Entry surface. The decorator makes `upload` an entry point."""

from flask import Flask, request

from .storage import save

server = Flask(__name__)


@server.route("/upload", methods=["POST"])
def upload():
    return save(request.args.get("name"), request.data)
