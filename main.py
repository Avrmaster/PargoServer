import json
from datetime import datetime
from functools import wraps
from crypt import mk_salt, hash_pass

from flask import Flask, request
from google.cloud import datastore

app = Flask(__name__)
__user_fields = ["email", "firstname", "prefix", "lastname", "address", "housenumber", "password"]


def __authorized(route_func):
    @wraps(route_func)
    def route_wrapper(*args, **kwargs):
        if "Authorization" in request.headers \
                and request.headers["Authorization"] == "Bearer LKNM123456":
            return route_func(*args, **kwargs)
        else:
            return json.dumps({"success": False, "cause": "unauthorized access"})
    return route_wrapper


def __requires_data(required_keys: list):
    def decorator(route_func):
        @wraps(route_func)
        def route_wrapper(*args, **kwargs):
            passed_data = request.get_json()
            if all([k in passed_data for k in required_keys]):
                return route_func(*args, **kwargs)
            else:
                missing_fields = [k for k in required_keys if k not in passed_data]
                return json.dumps({"success": False, "cause": f"not all needed fields were passed. "
                                                              f"Missing: {missing_fields}"})
        return route_wrapper
    return decorator


@app.route('/register/', methods=["POST"])
@__authorized
@__requires_data(__user_fields)
def register():
    ds = datastore.Client()
    user_data = request.get_json()

    query = ds.query(kind='user')
    query.add_filter("email", '=', user_data["email"])
    can_be_registered = len(list(query.fetch())) == 0
    response = {"success": can_be_registered}

    if can_be_registered:
        for k in user_data:
            if k not in __user_fields:
                del user_data[k]

        new_user = datastore.Entity(key=ds.key('user'))
        user_data["dynamic_salt"] = mk_salt()
        user_data["password"] = hash_pass(user_data["password"], user_data["dynamic_salt"])
        user_data["parcels"] = json.dumps([])

        new_user.update(user_data)
        ds.put(new_user)

        del user_data["dynamic_salt"]
        del user_data["password"]
        response["user"] = user_data
    else:
        response["cause"] = f"User with email {user_data['email']} is already registered"

    return json.dumps(response)


@app.route('/login/', methods=["POST"])
@__authorized
@__requires_data(["email", "password"])
def login():
    ds = datastore.Client()
    user_data = request.get_json()
    response = {}

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
            response["cause"] = "Invalid password"

    return json.dumps(response)


@app.route('/edit/', methods=["GET", "POST"])
@__authorized
@__requires_data(["email", "password"])
def edit():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


@app.route('/add_track_code/', methods=["GET", "POST"])
@__authorized
@__requires_data(["email", "password", "track_code"])
def add_track_code():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


if __name__ == '__main__':
    app.run(debug=True)
