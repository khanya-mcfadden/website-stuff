from flask import Flask, render_template
import sqlite3
connection = sqlite3.connect("users.db")
cursor = connection.cursor()
# Create a table with the name users
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL, admin BOOLEAN NOT NULL DEFAULT FALSE)")
cursor.execute(
    "INSERT INTO users (username, email, password, admin) VALUES ('admin', 'admin@gmail.com', '123456789', TRUE)")


cursor.execute("create table if not exists courses (course_id INTEGER PRIMARY KEY, course_name TEXT NOT NULL, course_description TEXT NOT NULL,course_duration TEXT NOT NULL)")
cursor.execute("INSERT INTO courses (course_name, course_description, course_duration) VALUES ('Python', 'Python is a high-level, interpreted, interactive and object-oriented scripting language.', '3 months')")
cursor.execute("INSERT INTO courses (course_name, course_description, course_duration) VALUES ('JavaScript', 'JavaScript is a programming language that is one of the core technologies of the World Wide Web.', '2 months')")
cursor.execute("INSERT INTO courses (course_name, course_description, course_duration) VALUES ('Java', 'Java is a high-level, class-based, object-oriented programming language that is designed to have as few implementation dependencies as possible.', '4 months')")
cursor.execute("INSERT INTO courses (course_name, course_description, course_duration) VALUES ('C++', 'C++ is a general-purpose programming language created as an extension of the C programming language.', '5 months')")
cursor.execute("INSERT INTO courses (course_name, course_description, course_duration) VALUES ('Ruby', 'Ruby is an interpreted, high-level, general-purpose programming language.', '3 months')")
cursor.execute("CREATE TABLE IF NOT EXISTS bookings (booking_id INTEGER PRIMARY KEY, courses text, username text, date TEXT, time TEXT, FOREIGN KEY(username) REFERENCES users(username))")
connection.commit()

connection.close()