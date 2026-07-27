from flask import Blueprint

tickets_bp = Blueprint('tickets', __name__, url_prefix='/tickets')

from . import tickets

incidents_bp = Blueprint('incidents', __name__, url_prefix='/incidents')

from . import incidents

assets_bp = Blueprint('assets', __name__, url_prefix='/assets')

from . import assets