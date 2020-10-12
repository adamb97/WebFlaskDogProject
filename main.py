"""Adam Benalayat SDEV300 Lab 8 10/13/2020
This program functions as the back end for a web page which displays dog breed facts upon
a user's registration and logging in
"""
import datetime
import logging
from flask import Flask, render_template, request, redirect, url_for, session
from passlib.handlers.sha2_crypt import sha256_crypt

app = Flask(__name__)
app.secret_key = 'abc123'



def check_pw(pw):
    """This funciton checks the password for complexity using regex"""
    # minimum length 8
    minfound = False
    lower_found = False
    upper_found = False
    digit_found = False
    if len(pw) >= 8:
        minfound = True
        for i in pw:
            if i.islower():
                lower_found = True
            elif i.isupper():
                upper_found = True
            elif i.isdigit:
                digit_found = True
    return minfound and lower_found and upper_found and digit_found


def is_common(pw):
    """This function checks to see if the password is a commmon password"""
    content = None
    with open("C:\\Users\\adben\\Downloads\\CommonPassword.txt") as f:
        content = f.read().splitlines()
    print(content)
    return pw in content
def get_current_date():
    """This function returns the current date"""
    x = datetime.datetime.now()
    return x


@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == "POST":
        entered_name = request.form['username']
        entered_pw = request.form['pwd']
        if check_pw(entered_pw):
            hashed_pw = sha256_crypt.hash(entered_pw)
            with open('passfile.txt', "a") as f:
                f.writelines(hashed_pw + "\n")
                f.close()
            with open('usernames.txt', "a") as f:
                f.writelines(entered_name + "\n")
                f.close()
            session['user'] = entered_name
            return redirect((url_for('welcome')))
        else:
            error = "You could not be registered"
    return render_template('register.html', error=error)

@app.route('/welcome')
def welcome():
    print(session)
    if 'user' in session:
        return render_template('welcome.html')
    else:
        print("User not logged in")
        return("Error. You need to log in")
@app.route('/changepwd', methods=['post','get'])
def changepwd():
    message = ''
    if request.method == "POST":
        newpwd = request.form.get('newPassword')
        oldpwd = request.form.get('password')
        #Confirm passwords match
        if newpwd.lower() != oldpwd.lower():
            message = "Passwords do not match.. Please try again"
            print(request.remote_addr)
            app.logger.error("(" + request.remote_addr + ")" + message)
        elif not check_pw(newpwd):
            message = "Password does not meet complexity standards"
        elif is_common(newpwd):
            message = "password is comonly used. Try again"
        else:
            return render_template('welcome.html')
    return render_template('changepwd.html', message=message)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return render_template('logout.html')
@app.route('/dalmatian')
def dalmatian():
    if 'user' in session:
        print(session)
        return render_template('dalmatian.html', get_current_date=get_current_date())
    else:
        print("User not logged in")
        return ("Error. You need to log in")



@app.route('/lab')
def lab():
    if 'user' in session:
        return render_template('lab.html')
    else:
        print("User not logged in")
        return ("Error. You need to log in")



@app.route('/dogTable')
def dogTable():
    if 'user' in session:
        return render_template('dogTable.html')
    else:
        print("User not logged in")
        return ("Error. You need to log in")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == "POST":
        #log usernames and passwords to txt file
        entered_name = request.form['username']
        entered_pw = request.form['pwd']
        f = open("usernames.txt", "r")
        f2 = open("passfile.txt", "r")
        lines = f.readlines()
        lines2 = f2.readlines()
        username_found = False
        pw_found = False
        for line in lines:
            if entered_name == line.strip():
                username_found = True
        for line1 in lines2:
            if sha256_crypt.verify(entered_pw, line1.strip()):
                pw_found = True
        if username_found and pw_found:
            session['user'] = entered_name
            return render_template('welcome.html')
        else:
            error = "You could not be logged in"
    return render_template('login.html', error=error)


@app.route('/beagle')
def beagle():
    if 'user' in session:
        return render_template('beagle.html')
    else:
        print("User not logged in")
        return ("Error. You need to log in")




if __name__ == "__main__":
    #configuring logging
    handler = logging.FileHandler('errors.log')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setLevel(logging.ERROR)
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.run()

