from flask import Flask, render_template
import flask_avatar
app = Flask(__name__)
avatar = flask_avatar.Avatar(app)
@app.route("/")
def home():
    avatar_url = f"https://robohash.org/negar.png"
    print(avatar_url)
    return render_template("test.html",avatar_url=avatar_url)

if __name__ == "__main__":
    app.run()