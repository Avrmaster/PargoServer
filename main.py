import json
from datetime import datetime
from flask import Flask, request
from google.cloud import datastore


app = Flask(__name__)


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


@app.route('/register', methods=["GET", "POST"])
def register():
    ds = datastore.Client()
    passed_data = json.load(request.data)

    new_user = datastore.Entity(key=ds.key('user'))
    new_user.update(passed_data)

    ds.put(new_user)
    return f"successfully created user from {json.dump(passed_data)}"


@app.route('/login', methods=["GET", "POST"])
def login():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


@app.route('/edit', methods=["GET", "POST"])
def edit():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


@app.route('/add_track_code', methods=["GET", "POST"])
def add_track_code():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


@app.route('/get_user', methods=["GET", "POST"])
def get_user():
    return f"Got {request.args} as a args. {request.data} as data. {request.form} as form. {request.values} as values"


if __name__ == '__main__':
    app.run(debug=True)
