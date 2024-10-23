import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy import String, ForeignKey
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
from forms import *
from functools import wraps
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#  Building a login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


##CONFIGURE TABLES
class Comment(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True, nullable=False)
    text: Mapped[str] = mapped_column(nullable=False)
    parent_id: Mapped[int] = mapped_column(ForeignKey("user_p.id"))
    user_parent_relation = relationship("User",back_populates="children_comment")
    blog_parent_id : Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    blog_parent_relation = relationship("BlogPost",back_populates="children")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id : Mapped[int] = mapped_column(ForeignKey("user_p.id"))
    parent_relation = relationship("User",back_populates="children_post")
    children = relationship(Comment,back_populates="blog_parent_relation")



class User(UserMixin, db.Model):
    __tablename__ = "user_p"
    id: Mapped[int] = mapped_column(primary_key=True, nullable=False)
    email: Mapped[str] = mapped_column(nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    children_post = relationship(BlogPost,back_populates="parent_relation")
    children_comment = relationship(Comment, back_populates="user_parent_relation")




with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(func):
    @wraps(func)
    def decorated_func(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return func(*args, **kwargs)
            else:
                return redirect(url_for("unauthorized"))
        else:
            return redirect(url_for("login"))
    return decorated_func


@app.route("/unauthorized")
def unauthorized():
    return "You are not authorized to access this page.", 403


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    admin_id = request.args.get("admin_id", False)
    return render_template("index.html", all_posts=posts, admin_id=admin_id)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = CreateRegisterForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_pass = werkzeug.security.generate_password_hash(password)
        name = request.form.get("name")
        check_user = User.query.filter_by(email=email).first()
        if not check_user:
            new_user = User(
                email=email,
                password=hashed_pass,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
        else:
            flash("user already exists please login")
            return redirect(url_for("login"))
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            database_pass = user.password

            if check_password_hash(password=password, pwhash=database_pass):
                login_user(user)
                if user.id ==1:
                    admin_id = True
                    return redirect(url_for("get_all_posts", admin_id=admin_id))
                return redirect(url_for("get_all_posts"))
            else:
                flash("incorrect password", "error")
                return redirect(url_for("login"))
        else:
            flash("user doesn't exists", "error")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods =["POST","GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comment = request.form.get("comment")
    all_comments = db.session.query(Comment).all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment,
                parent_id=current_user.id,
                blog_parent_id=post_id

            )
            db.session.add(new_comment)
            db.session.commit()
            data_base_comments = Comment.query.filter_by(blog_parent_id=post_id)
            return redirect(url_for("show_post",post_id=post_id,data_base_comments=data_base_comments))
        else:
            flash("please login to submit a comment","error")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post,form=form,all_comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=["POST","GET"])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            id=current_user.id,
            parent_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body

    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.context_processor
def inject_logged_in():
    return dict(logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000)
