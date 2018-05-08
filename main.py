import json
from datetime import datetime
from functools import wraps
from crypt import mk_salt, hash_pass

from flask import Flask, request
from google.cloud import datastore

app = Flask(__name__)
__user_fields = ["email", "firstname", "prefix", "lastname", "address", "housenumber"]


def __authorized(route_func):
    @wraps(route_func)
    def route_wrapper(*args, **kwargs):
        if "Authorization" in request.headers \
                and request.headers["Authorization"] == "Bearer LKNM123456":
            return route_func(*args, **kwargs)
        else:
            return json.dumps({"success": False, "cause": "unauthorized access"})

    return route_wrapper


def __requires_keys(required_keys: list):
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


def __returns_user(route_func):
    @wraps(route_func)
    def route_wrapper(*args, **kwargs):
        route_func(*args, **kwargs)
        user = kwargs["user"]
        if "dynamic_salt" in user:
            del user["dynamic_salt"]
        if "password" in user:
            del user["password"]
        return json.dumps({"success": True, "user": user})
    return route_wrapper()


def __requires_login(route_func):
    @wraps(route_func)
    def route_wrapper(*args, **kwargs):
        response = {}
        ds = datastore.Client()
        passed_data = request.get_json()
        email = passed_data["email"]
        password = passed_data["password"]

        query = ds.query(kind='user')
        query.add_filter("email", '=', email)
        results = list(query.fetch())
        if len(results) < 1:
            response["success"] = False
            response["cause"] = "User with given email does not exist"
        else:
            user = results[0]
            if hash_pass(password, user["dynamic_salt"]) == user["password"]:
                return route_func(ds=ds, user=user, *args, **kwargs)
            else:
                response["success"] = False
                response["cause"] = "Invalid password"
        return json.dumps(response)

    return route_wrapper


@app.route('/register/', methods=["POST"])
@__authorized
@__requires_keys(__user_fields + ["password"])
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
@__requires_keys(["email", "password"])
@__returns_user
@__requires_login
def login(ds, user: dict):
    pass


@app.route('/edit/', methods=["POST"])
@__authorized
@__requires_keys(["email", "password"])
@__returns_user
@__requires_login
def edit(ds, user: dict):
    passed_data = request.get_json()
    for key in passed_data:
        if key in __user_fields:
            user[key] = passed_data[key]
    ds.put(user)


@app.route('/add_track_code/', methods=["POST"])
@__authorized
@__requires_keys(["email", "password", "track_code"])
@__returns_user
@__requires_login
def add_track_code(ds, user: dict):
    passed_data = request.get_json()
    parcels = json.loads(user["parcels"])
    new_track_code = passed_data["track_code"]
    if new_track_code not in parcels:
        parcels.add(new_track_code)
    user["parcels"] = json.dumps(parcels)
    ds.put(user)


@app.route('/remove_track_code/', methods=["POST"])
@__authorized
@__requires_keys(["email", "password", "track_code"])
@__returns_user
@__requires_login
def remove_track_code(ds, user: dict):
    passed_data = request.get_json()
    parcels = json.loads(user["parcels"])
    old_track_code = passed_data["track_code"]
    if old_track_code in parcels:
        parcels.remove(old_track_code)
    user["parcels"] = json.dumps(parcels)
    ds.put(user)


if __name__ == '__main__':
    app.run(debug=True)
