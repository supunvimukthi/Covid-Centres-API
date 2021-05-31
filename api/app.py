from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
from builtins import str

from flask import Flask, jsonify, request, make_response
from flask_restplus import Api, Namespace, Resource, fields
from flask_cors import CORS, cross_origin
from flask_pymongo import PyMongo
from flask_restplus.fields import Integer
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

load_dotenv()  # take environment variables from .env

DEFAULT_SERVER_PORT = 5100
DB_NAME = "CovidCentres"

logger = logging.getLogger(__name__)
app = Flask(__name__)

api = Api(app,
          title="Covid Centres API",
          description="A simple API to store and retrieve available bed count for each covid centre in the country")
covid = Namespace('v1/covid', description='Covid Centres Controller')
api.add_namespace(covid)
# if not cors_origins:
cors_origins = []
CORS(app, origins='*',
     headers=['Content-Type', 'Authorization'],
     expose_headers='Authorization')

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
app.config['MONGO_URI'] = 'mongodb://mongoadmin:4?pT98LJH5@mongodb:27017/{}?authSource=admin'.format(DB_NAME)
mongo = PyMongo(app)

value_fields = covid.model('Covid Centre', {
    "name": fields.Raw(required=True,
                       description="name of the covid centre"),
    "location": fields.String(required=True,
                              description="location of the covid centre"),
    "contact": fields.Integer(required=True,
                              description="contact number for the covid centre"),
    "username": fields.Integer(required=True,
                               description="username for the covid centre"),
    "password": fields.Integer(required=True,
                               description="password for the covid centre")
})

bed_fields = covid.model('Covid Centre', {
    "beds": fields.Raw(required=True,
                       description="number of beds available in the covid centre"),
    "time": fields.String(required=True,
                              description="updated timestamp"),
    "desc": fields.Integer(required=True,
                              description="any notes"),
})


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        Users = mongo.db["Users"]
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.find({'public_id': data['public_id']})
            current_user = [user for user in current_user][0]
        except Exception as e:
            return jsonify({'message': 'token is invalid', 'error': str(e)})

        return f(current_user, *args, **kwargs)

    return decorator


@api.route('/login')
class Login(Resource):
    @cross_origin(origins=cors_origins)
    @covid.doc('user login endpoint', )
    def get(self):
        """ user login endpoint """
        auth = request.authorization
        users = mongo.db["Users"]

        if not auth or not auth.username or not auth.password:
            return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

        user = users.find({'username': auth.username})
        user = [u for u in user]
        if len(user) == 0:
            return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "no such user found"'})
        else:
            user = user[0]

        if check_password_hash(user['hashed'], auth.password):
            token = jwt.encode(
                {'public_id': user['public_id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                app.config['SECRET_KEY'],
                algorithm="HS256"
            )
            print(token)
            covid_centres = mongo.db["CovidCentres"]
            centres = covid_centres.find({'username': auth.username}, {'_id': 0, 'password': 0})
            centre = [cent for cent in centres]
            return jsonify({'token': token, 'data': centre})

        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@cross_origin(origins=cors_origins)
@covid.route('/centre/bed')
class SetBeds(Resource):
    @token_required
    @covid.doc('Set available beds for a given covid centre along with the timestamp', )
    def post(self, id):
        """ Set available beds for a given covid centre along with the timestamp """
        try:
            json_data = request.json
            covid_centre_beds = mongo.db["CovidCentre_Beds"]
            covid_centres = mongo.db["CovidCentres"]
            covid_centre_beds.insert_one({
                'username': self['username'],
                'beds': json_data['beds'],
                'time': json_data['time'],
                'desc': json_data['desc']
            })
            covid_centres.update(
                {'username': self['username']},
                {'$set':
                    {
                        'beds': json_data['beds'],
                        'desc': json_data['desc'],
                        'updated': json_data['time'],
                    }
                }
            )
            return jsonify({
                "results": 'successfully updates the bed count({}) for the centre {}'.format(
                    str(json_data['beds']),
                    self['username']
                )})
        except Exception as e:
            return make_response('error', 400, {"error": str(e)})

        return jsonify({
            "message": "Successfully added the centre {}".format(json_data['name']),
            "centre_id": centre.inserted_id
        })


@cross_origin(origins=cors_origins)
@covid.route('/centre/beds')
class GetBeds(Resource):
    @token_required
    @covid.response(404, 'covid centre data not found')
    @covid.param('id', 'username for the covid centre')
    @covid.doc('Fetch available beds for a given covid centre with all the past data', )
    def get(self, id):
        print(id)
        """ Fetch available beds for a given covid centre with all the past data """
        covid_centre_beds = mongo.db["CovidCentre_Beds"]
        all_data = covid_centre_beds.find({'username': self['username']}, {'_id': 0})
        return jsonify({"results": [sample for sample in all_data]})


@cross_origin(origins=cors_origins)
@covid.route('/centres')
class GetCentres(Resource):
    @token_required
    @covid.doc('Fetch all covid centres listed in the db with their latest available bed counts', )
    def get(self, id):
        """Fetch all covid centres listed in the db with their latest available bed counts """
        covid_centres = mongo.db["CovidCentres"]
        all_covid_centres = covid_centres.find({}, {'_id': 0})
        return jsonify({"results": [centre for centre in all_covid_centres]})


@cross_origin(origins=cors_origins)
@covid.route('/centre')
class AddCentre(Resource):
    @token_required
    @covid.doc('add new covid centre to the db', )
    @covid.expect(value_fields)
    def post(self, id):
        """ add new covid centre to the db """
        if self['username'] != 'admin':
            return make_response('no access', 400, {"error": 'you need to have admin access to perform this task'})
        try:
            json_data = request.json
            covid_centres = mongo.db["CovidCentres"]
            users = mongo.db["Users"]
            us = users.find({'username': json_data['username']})
            us = [u for u in us]
            if len(us) > 0:
                return jsonify({
                    'message': 'error',
                    'error': 'username {} already exists. Please use a different username'.format(json_data['username'])
                })
            new_centre = {
                'name': json_data['name'],
                'location': json_data['district'],
                'province': json_data['province'],
                'contact': json_data['contact'],
                'created': datetime.datetime.now(),
                'username': json_data['username'],
                'password': json_data['password'],
                'beds': 'not updated',
                'time': 'not updated',
                'desc': ''
            }
            hashed_password = generate_password_hash(json_data['password'], method='sha256')
            users.insert_one({
                'name': json_data['name'],
                'username': json_data['username'],
                'password': json_data['password'],
                'hashed': hashed_password,
                'public_id': str(uuid.uuid4())
            })
            centre = covid_centres.insert_one(new_centre)

        except Exception as e:
            return make_response('error', 400, {"error": str(e)})

        return jsonify({
            "message": "Successfully added the centre {}".format(json_data['name']),
            "centre_id": str(centre.inserted_id)
        })


@cross_origin(origins=cors_origins)
@api.route("/health")
class Health(Resource):
    """Ping endpoint to check if the server is running and well."""

    @api.doc('Ping endpoint to check if the server is running and well.', )
    def get(self):
        return jsonify({"status": "ok"})


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("matplotlib").setLevel(logging.WARN)

    logger.info("Starting action endpoint server...")
    app.run(port=DEFAULT_SERVER_PORT, threaded=True, debug=False)

