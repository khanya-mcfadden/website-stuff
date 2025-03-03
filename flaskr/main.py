from datetime import datetime, timedelta
import os
import sqlite3
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import re


app = Flask(__name__)
app.secret_key = "1mads"


# Ensure the table is created when the app starts
def init_db():
    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()
    # Create the user table if it doesn't exist
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL, admin BOOLEAN NOT NULL DEFAULT FALSE)"
    )

    cursor.execute(
        "CREATE TABLE IF NOT EXISTS bookings (booking_id INTEGER PRIMARY KEY, assesor text, username text, date TEXT, time TEXT, FOREIGN KEY(username) REFERENCES user(username))"
    )

    connection.commit()
    connection.commit()
    connection.close()


# Initialize the database when the app starts
def initialize():
    init_db()


@app.before_request
def manage_session():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

    if "username" in session:
        # Check if session has expired
        last_activity = session.get("last_activity")
        if last_activity:
            current_time = datetime.now()
            time_difference = current_time - last_activity.replace(tzinfo=None)
            if time_difference.total_seconds() > 1800:  # 30 minute
                session.clear()
                return redirect(url_for("login"))

    # Update the last activity timestamp for the session
    session["last_activity"] = datetime.now()


@app.context_processor
def inject_user():
    return {
        "authenticated": "username" in session,
        "admin": session.get("admin", False),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/BookingPage", methods=["GET", "POST"])
def BookingPage_page():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        assesor = request.form.get("assesor")
        date = request.form.get("date")
        time = request.form.get("time")

        if not assesor or not date or not time:
            return "Please fill out all fields", 400

        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()

        # Create bookings table if it doesn't exist
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                booking_id INTEGER PRIMARY KEY,
                assesor id INTEGER,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                username TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES user(username)
            )
        """
        )

        try:
            # Insert the booking
            cursor.execute(
                "INSERT INTO bookings (assesor, date, time, username) VALUES (?, ?, ?, ?)",
                (assesor, date, time, session.get("username")),
            )
            connection.commit()
            connection.close()
            return redirect("/booking_confirm")
        except sqlite3.Error as e:
            connection.close()
            return f"Booking failed: {e}", 500

    # Fetch available assesor from the database
    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM assesor")  # Adjust table/column names as needed
    booking = cursor.fetchall()
    connection.close()

    # Pass courses to the template
    return render_template(
        "BookingPage.html", assesor=[assesor[0] for assesor in booking]
    )


@app.route("/unfinishedpagepage", methods=["GET", "POST"])
def unfinishedpage_page():
    return render_template("unfinished.html")


@app.route("/Orderingpage", methods=["GET", "POST"])
def Orderingpage_page():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("Orderingpage.html")


@app.route("/Order", methods=["GET", "POST"])
def Order():
    if "username" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        item = request.form.get("product")
        quantity = request.form.get("quantity")

        if not item or not quantity:
            return ("Please fill out all fields",)

        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()

        # Create orders table if it doesn't exist
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id INTEGER PRIMARY KEY,
                item TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                username TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES user(username)
            )
        """
        )

        try:
            # Insert the order
            cursor.execute(
                "INSERT INTO orders (item, quantity, username) VALUES (?, ?, ?)",
                (item, quantity, session.get("username")),
            )
            connection.commit()
            connection.close()
            return redirect("/ordering_confirm")
        except sqlite3.Error:
            connection.close()
            return "Order failed", 500
    return render_template("Orderingpage.html")


@app.route("/test")
def test_page():
    return render_template("test.html")


@app.route("/about_page")
def about_page():
    return render_template("about.html")


@app.route("/confirm")
def confirm():
    return render_template("confirm.html")


@app.route("/booking_confirm")
def booking_confirm():
    return render_template("booking_confirm.html")


@app.route("/ordering_confirm")
def ordering_confirm():
    return render_template("ordering_confirm.html")


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    # Verify user exists in database
    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()

    # Check if user exists in database
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        connection.close()
        session.pop("username", None)  # Clear invalid session
        return redirect(url_for("login"))

    # Fetch user-specific bookings
    cursor.execute("SELECT * FROM bookings WHERE username = ?", (username,))
    bookings = cursor.fetchall()
    connection.close()

    return render_template("profile.html", username=username, bookings=bookings)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate input lengths
        if len(username) > 200 or len(password) > 200:
            return "Input exceeds character limit", 400

        # Check if the user exists in the database
        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()

        # Modified query to include admin column
        cursor.execute(
            "SELECT username, password, admin FROM user WHERE username = ?",
            (username,),
        )
        user = cursor.fetchone()
        connection.close()

        if user:
            admin = user[2]  # Get admin status
            if admin:
                # For admin accounts, direct password comparison
                if password == user[1]:  # Direct comparison for admin passwords
                    session["username"] = username
                    session["admin"] = True
                    return redirect(url_for("profile"))
            else:
                # For regular user, check hashed password
                if check_password_hash(user[1], password):
                    session["username"] = username
                    session["admin"] = False
                    return redirect(url_for("profile"))

        return "Invalid username or password", 400

    return render_template("login.html")


@app.route("/Sign-Up", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            return "Please fill out all fields", 400  # Simple error handling

        # Validate input lengths
        if len(username) > 15 or len(email) > 50 or len(password) > 20:
            return "Input exceeds character limit", 400
        if len(username) < 3 or len(email) < 3 or len(password) < 8:
            return "Input is below character limit", 400

        # Validate characters in username and email
        if (
            not re.match("^[a-zA-Z0-9@._!;#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$", username)
            or not re.match("^[a-zA-Z0-9@._!;#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$", email)
            or not re.match(
                "^[a-zA-Z0-9@._!;#$%&'()*+,-./:;<=>?@[\]^_`{|}~]+$", password
            )
        ):
            return "Invalid characters in username, email or password", 400
        # Validate password strength
        if not re.match(
            r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_\-+=<>?.,]).{8,}$",
            password,
        ):
            return (
                "Password must contain at least 8 characters, including uppercase, lowercase, digits, and special characters.",
                400,
            )
        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Insert user into database
        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()

        # Check if the username or email already exists
        cursor.execute(
            "SELECT * FROM user WHERE username = ? OR email = ?", (username, email)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            connection.close()
            return "Username or email already exists.", 400

        try:
            # Insert the user
            cursor.execute(
                "INSERT INTO user (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            return "User already exists or email is already registered.", 400
        finally:
            connection.close()

        # Redirect to confirmation page
        return redirect("/confirm")

    return render_template("Sign-Up.html")


@app.route("/weather_page")
def health():
    return render_template("weather_page.html")


@app.route("/theme", methods=["POST"])
def set_theme():
    theme = request.form.get("theme")
    session["theme"] = theme
    return "", 204


@app.context_processor
def inject_theme():
    theme = session.get("theme", "light")
    return dict(theme=theme)


def inject_user():
    return {"is_authenticated": "username" in session}


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not all([current_password, new_password, confirm_password]):
            return ("Please fill out all fields",)

        if new_password != confirm_password:
            return "New passwords do not match", 400

        if len(new_password) < 8 or len(new_password) > 20:
            return "New password must be between 8 and 20 characters", 400

        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()

        cursor.execute(
            "SELECT password FROM user WHERE username = ?", (session["username"],)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user[0], current_password):
            connection.close()
            return "Current password is incorrect", 400

        hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
        cursor.execute(
            "UPDATE user SET password = ? WHERE username = ?",
            (hashed_password, session["username"]),
        )
        connection.commit()
        connection.close()

        return render_template("profile.html")

    return render_template("profile.html")


@app.route("/usersinfo")
def users_info():
    if "username" not in session or not session.get("admin"):
        return redirect(url_for("login"))

    try:
        connection = sqlite3.connect("user.db")
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, email, admin FROM user")
        user = cursor.fetchall()

        cursor.execute("SELECT booking_id, assesor, username, date, time FROM bookings")

        bookings = cursor.fetchall()

        connection.close()
        return render_template("users_info.html", user=user, bookings=bookings)
    except sqlite3.Error as e:
        return f"Database error: {str(e)}", 500


@app.route("/add_booking", methods=["POST"])
def add_booking():
    if "username" not in session:
        return redirect(url_for("login"))

    assesor = request.form.get("assesor")
    date = request.form.get("date")
    time = request.form.get("time")

    if not assesor or not date or not time:
        return "Please fill out all fields", 400

    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()

    try:
        # Insert the new booking
        cursor.execute(
            "INSERT INTO bookings (assesor, date, time, username) VALUES (?, ?, ?, ?)",
            (assesor, date, time, session.get("username")),
        )
        connection.commit()
        connection.close()
        return redirect("/profile")
    except sqlite3.Error as e:
        connection.close()
        return f"Failed to add booking: {e}", 500


@app.route("/delete_booking", methods=["POST"])
def delete_booking():
    if "username" not in session:
        return redirect(url_for("login"))

    booking_id = request.form.get("booking_id")
    if not booking_id:
        return "Please provide a booking ID", 400

    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM bookings WHERE booking_id = ?", (booking_id,))
        connection.commit()
        connection.close()
        return redirect("/profile")
    except sqlite3.Error as e:
        connection.close()
        return f"Failed to delete booking: {e}", 500


@app.route("/delete_user", methods=["POST"])
def delete_user():
    if "username" not in session or not session.get("admin"):
        return redirect(url_for("login"))

    user_id = request.form.get("user_id")

    if not user_id:
        return "Please provide a user ID", 400

    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        connection.commit()
        connection.close()
        return redirect("/usersinfo")
    except sqlite3.Error as e:
        connection.close()
        return f"Failed to delete user: {e}", 500  # Internal server error


@app.route("/set_cookie", methods=["POST"])
def set_cookie():
    response = make_response(redirect(url_for("index")))
    response.set_cookie("cookie_consent", "true", max_age=60 * 60 * 24 * 365)  # 1 year
    return response


@app.route("/search", methods=["GET"])
def search():
    if "username" not in session or not session.get("admin"):
        return redirect(url_for("login"))

    query = request.args.get("q", "").lower()
    connection = sqlite3.connect("user.db")
    cursor = connection.cursor()

    # Search user
    cursor.execute(
        "SELECT id, username, email FROM user WHERE LOWER(username) LIKE ? OR LOWER(email) LIKE ?",
        (f"%{query}%", f"%{query}%"),
    )
    user = cursor.fetchall()

    # Search bookings
    cursor.execute(
        "SELECT booking_id, assesor, username, date, time FROM bookings WHERE LOWER(bookings) LIKE ? OR LOWER(username) LIKE ?",
        (f"%{query}%", f"%{query}%"),
    )
    bookings = cursor.fetchall()

    connection.close()
    return jsonify({"user": user, "bookings": bookings})


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/weather_page")
def weather_page():
    return render_template("weather_page.html")


@app.route("/weather_data")
def get_weather_data():
    api_key = "0f98d01acd0e41818d8124023242111"
    location = request.args.get(
        "location", "horsham"
    )  # Get location from query params, default to horsham
    url = f"https://api.weatherapi.com/v1/forecast.json?key={api_key}&q={location}&days=4&aqi=no"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError if the status is 4xx, 5xx
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch weather data", "details": str(e)})


@app.route("/Ai_data", methods=["POST"])
def get_Ai():
    import google.generativeai as genai
    from flask import request, jsonify

    genai.configure(api_key="AIzaSyCVadfEkISEXbfrKKWoXBgz2sCbFxMjLPY")

    model = genai.GenerativeModel("gemini-1.5-flash")
    chat = model.start_chat(
        history=[
            {"role": "user", "parts": "Hello"},
            {
                "role": "model",
                "parts": "Great to meet you. What would you like to know?",
            },
        ]
    )

    data = request.get_json()
    question = data.get("question")

    response = chat.send_message(question)
    response_text = response.text

    # Function to check if the response is related to what is needed(currantly uneeded)
    def is_relevant_response(response):
        keywords_1 = []
        keywords_2 = []
        return any(keyword in response.lower() for keyword in keywords_1 + keywords_2)

    # Filter the response
    if is_relevant_response(response_text):
        return jsonify(
            {
                "response1": response_text,
            }
        )
    else:
        return jsonify(
            {
                "response1": "Sorry, I can only talk about weather or health.",
                "response2": "",
            }
        )


@app.route("/articles_page")
def articles_page():
    return render_template("articles.html")


# Error handler for 404
@app.errorhandler(404)
def page_not_found(_):
    app.logger.error(f"Page not found: {request.url}")
    return render_template("404.html"), 404


if __name__ == "__main__":
    initialize()
    app.run(debug=True, host="0.0.0.0")