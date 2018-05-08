import json
from datetime import datetime
from functools import wraps
from crypt import mk_salt, hash_pass

from flask import Flask, request
from google.cloud import datastore

app = Flask(__name__)


def authorized(route_func):
    @wraps(route_func)
    def route_wrapper():
        if "Authorization" in request.headers \
                and request.headers["Authorization"] == "Bearer LKNM123456":
            return route_func()
        else:
            return json.dumps({"success": False, "cause": "unauthorized access"})

    return route_wrapper


@app.route('/mainpage/')
def mainpage():
    ds = datastore.Client()

    user_ip = request.remote_addr

    entity = datastore.Entity(key=ds.key('visit'))
    entity.update({
        'user_ip': user_ip,
        'timestamp': datetime.utcnow()
    })

    ds.put(entity)

    query = ds.query(kind='visit', order=('-timestamp',))

    results = [
        'Time: {timestamp} Addr: {user_ip}'.format(**x)
        for x in query.fetch(limit=10)]

    output = 'Last 10 visits:\n{}'.format('\n'.join(results))

    return output, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/register/', methods=["POST"])
def register():
    ds = datastore.Client()
    user_data = request.get_json()
    response = {}

    if "email" not in user_data or \
            "FirstName" not in user_data or \
            "Prefix" not in user_data or \
            "Lastname" not in user_data or \
            "Address" not in user_data or \
            "HouseNumber" not in user_data or \
            "Password" not in user_data:
        can_be_registered = False
        response["cause"] = "Not all needed for registration data was provided"
    else:
        query = ds.query(kind='user')
        query.add_filter("email", '=', user_data["email"])
        can_be_registered = len(list(query.fetch())) == 0
        response = {"success": can_be_registered}

    if can_be_registered:
        new_user = datastore.Entity(key=ds.key('user'))

        user_data["dynamic_salt"] = mk_salt()
        user_data["password"] = hash_pass(user_data["password"], user_data["dynamic_salt"])
        user_data["parcels"] = json.dumps([])

        new_user.update(user_data)
        ds.put(new_user)

        del user_data["dynamic_salt"]
        del user_data["password"]
        response["user"] = user_data
    elif "cause" not in response:
        response["cause"] = f"User with email {user_data['email']} is already registered"

    return json.dumps(response)


@app.route('/login/', methods=["POST"])
def login():
    ds = datastore.Client()
    user_data = request.get_json()
    response = {}

    if "email" not in user_data or \
            "password" not in user_data:
        response["success"] = False
        response["cause"] = "Not all needed for login data was provided"
    else:
        query = ds.query(kind='user')
        query.add_filter("email", '=', user_data["email"])
        results = list(query.fetch())
        if len(results) < 1:
            response["success"] = False
            response["cause"] = "User with given email does not exist"
        else:
            user = results[0]
            if hash_pass(user_data["password"], user["dynamic_salt"]) == user["password"]:
                response["success"] = True
                del user["dynamic_salt"]
                del user["password"]
                response["user"] = user
            else:
                response["success"] = False
                response["cause"] = "Invalid email/password combination"

    return json.dumps(response)


@app.route('/edit/', methods=["GET", "POST"])
def edit():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


@app.route('/add_track_code/', methods=["GET", "POST"])
@authorized
def add_track_code():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


if __name__ == '__main__':
    app.run(debug=True)
