from flask import Flask ,jsonify, make_response,request,url_for
from flask_sqlalchemy import SQLAlchemy
from flask.json import JSONEncoder
from sqlalchemy import or_,and_
from flask_cors import CORS, cross_origin
from flask.ext.bcrypt import Bcrypt
import jwt , datetime


app = Flask(__name__)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ycrhcrhfrcjqyz:7fd8060bfcdad4071b1495b4faf829e61550cb291535b465a402fb0fca64d29e@ec2-54-163-234-4.compute-1.amazonaws.com:5432/det2gahm246c0g'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)


class UserJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, User):
            return {
                'id': obj.id,
                'name': obj.name,
                'email': obj.email,
                'password': obj.password,
                'Role': obj.Role,
            }
        elif isinstance(obj, Report):
            return {
                'id': obj.id,
                'rType': obj.rType,
                'city': obj.city,
                'image': obj.image,
                'no': obj.no,
                'description': obj.description,
                'user': obj.user,
            }
        elif isinstance(obj, ReportStatus):
            return {
                'id': obj.id,
                'status': obj.status,
                'admin': obj.admin,
                'report': obj.report,
            }
        return super(UserJSONEncoder, self).default(obj)


app.json_encoder = UserJSONEncoder



class User(db.Model):
    __tablename__ = 'userFlask'
    id = db.Column(db.Integer,primary_key=True,autoincrement=True,unique=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    password = db.Column(db.String(120))
    Role = db.Column(db.Boolean)


    def __init__(self,name,email,password,Role):
        # self.id  = id
        self.name  = name
        self.email  = email
        self.Role  = Role
        self.password  = self.encrypt(password)


    def __init__(self,data):
        self.name = data['name']
        self.email = data['email']
        self.password = self.encrypt(data['password'])
        self.Role = data['Role']

    def __repr__(self):
        return  '<User %r>' % self.name

    def encrypt(self, password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def decrypt(self, enteredPassword):
        return bcrypt.check_password_hash(self.password, enteredPassword)

    def generateToken(self):
        return jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=180), 'id': self.id},
                          "secret", algorithm='HS256').decode()

    @staticmethod
    def verifyToken(token):
        return jwt.decode(token, "secret")['id']

# db.create_all()

class Report(db.Model):
    __tablename__ = 'reportFlask'
    id = db.Column(db.Integer,primary_key=True,autoincrement=True,unique=True)
    rType = db.Column(db.String(120))
    city = db.Column(db.String(120))
    image = db.Column(db.String(120))
    no = db.Column(db.String(120))
    description = db.Column(db.String(120))
    user = db.Column(db.Integer,db.ForeignKey('userFlask.id'))


    def __init__(self,rType,city,image,no,description,user):
        # self.id  = id
        self.rType  = rType
        self.city  = city
        self.image  = image
        self.no  = no
        self.description  = description
        self.user  = user


    def __init__(self,data):
        self.rType = data['rType']
        self.city = data['city']
        self.image = data['image']
        self.no = data['no']
        self.description = data['description']
        # self.user = data['user']

    def __repr__(self):
        return  '<User %r>' % self.rType
# db.create_all()

class ReportStatus(db.Model):
    __tablename__ = 'reportStatusFlask'
    id = db.Column(db.Integer,primary_key=True,autoincrement=True,unique=True)
    admin = db.Column(db.Integer,db.ForeignKey('userFlask.id'))
    report = db.Column(db.Integer,db.ForeignKey('reportFlask.id'))
    status = db.Column(db.String(120))



    def __init__(self,admin,report,status):
        # self.id  = id
        self.admin  = admin
        self.report  = report
        self.status  = status


    def __init__(self,uID,rID,status):
        self.admin = uID
        self.report = rID
        self.status = status

    def __repr__(self):
        return  '<User %r>' % self.status

db.create_all()

@app.route('/signup', methods = ['POST'])
def signup():
    email = request.json['email']
    if len(User.query.filter_by(email=email).all()) == 0:
        user = User(request.json)
        db.session.add(user)
        db.session.commit()
        token = user.generateToken()
        return jsonify({'data': {"user": user, "token": token}, 'message': 'Sucessfully Registered', 'error': ''})
    return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'User with ' + email + ' Already registered'}), 409)


@app.route('/login', methods = ['POST'])
def login():
    try:
        email = request.json['email']
        password = request.json['password']
    except:
        return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Parameters'}), 404)
    else:
        user = User.query.filter_by(email=email).all()
        if len(user) != 0:
            user = user[0]
            if user.decrypt(enteredPassword=password) == True:
                token = user.generateToken()
                return jsonify({'data': {'user': user, 'token': token},'message': 'Sucessfully Login', 'error': ''})
            else:
                return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Password'}), 401)
        return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid email'}), 401)

@app.route('/submitReport', methods = ['POST'])
def submitReport():
    try:
        token = request.headers['token']
    except:
        return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
    else:
        try:
            id = User.verifyToken(token=token)
        except:
            return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
        else:
            try:
                city = request.json['city']
                image = request.json['image']
                no = request.json['no']
                description = request.json['description']
                rType = request.json['rType']

            except:
                return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Parameter'}),400)
            else:
                user = User.query.filter_by(id=id).all()
                if len(user) == 0:
                    return make_response( jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid User ID'}),400)
                else:
                    user = user[0]
                    report = Report(request.json)
                    report.user = user.id
                    db.session.add(report)
                    db.session.commit()
                    return jsonify({'data': report, 'message': 'Your report has been submitted sucessfully', 'error': ''})


@app.route('/getAllReports', methods = ['GET'])
def getAllReports():
    try:
        token = request.headers['token']
    except:
        return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
    else:
        try:
            id = User.verifyToken(token=token)
        except:
            return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
        else:
            user = User.query.filter_by(id=id).all()
            if len(user) == 0:
                return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid User ID'}),404)
            else:
                if user[0].Role == True:
                    allReports = Report.query.filter_by(user=id).all()
                else:
                    allReports = Report.query.all()
                return jsonify({'data': allReports, 'message': 'Sucessfull', 'error': ''})


@app.route('/getAllReportsWithCity', methods = ['POST'])
def getAllReportsWithCity():
    try:
        token = request.headers['token']
    except:
        return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
    else:
        try:
            id = User.verifyToken(token=token)
        except:
            return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid token'}), 404)
        else:
            try:
                city = request.json['city']
            except:
                return make_response(jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Parameter'}),404)
            else:
                user = User.query.filter_by(id=id).all()
                if len(user) == 0:
                    return make_response( jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid User ID'}),404)
                else:
                    user = user[0]
                    if user.Role == False:
                        allReports = Report.query.filter_by(city=city).all()
                    else:
                        allReports = Report.query.filter_by(user=user.id, city=city).all()
                    return jsonify({'data': allReports, 'message': 'Sucessfull', 'error': ''})


@app.route('/SubmitStatus', methods = ['POST'])
def SubmitStatus():
        try:
            uID = request.form['uid']
            rID = request.form['rid']
            aID = request.form['aid']
            status = request.form['status']

        except:
            return jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Parameter'})
        else:
            admin = User.query.filter_by(id=aID).all()
            user = User.query.filter_by(id=uID).all()
            report = Report.query.filter_by(id=rID).all()

            if len(admin) != 0  and report != 0 and user != 0:
                admin = admin[0]
                user=user[0]
                report = report[0]
                if admin.Role == False:
                    reportStatus = ReportStatus.query.filter_by(admin=user.id,report=report.id).all()
                    if reportStatus:
                        firstReport = reportStatus[0]
                        firstReport.status = status
                        db.session.add(firstReport)
                        db.session.commit()
                        return jsonify({'data': '', 'message': 'Your status has been Updated', 'error': ''})
                    else:
                        reportStatus = ReportStatus(uID=uID,rID=rID,status=status)
                        db.session.add(reportStatus)
                        db.session.commit()
                        return jsonify({'data': '', 'message': 'Your status has been submitted', 'error': ''})
                else:
                    return jsonify({'data': '', 'message': '', 'error': 'You have not access to submit status'})

            else:
                return jsonify({'data': '', 'message': '', 'error': 'Invalid userID/reportID/adminID'})

@app.route('/getStatus', methods = ['POST'])
def getStatus():
    try:
        uID = request.form['uid']
        rID = request.form['rid']
    except:
        return jsonify({'data': '', 'message': 'Failed', 'error': 'Invalid Parameter'})
    else:
        user = User.query.filter_by(id=uID).all()
        if len(user) != 0:
            user = user[0]
            report = Report.query.filter_by(id=rID, user=user.id).all()
            if len(report) != 0:
                report = report[0]
                reportStatus = ReportStatus.query.filter_by(admin=user.id, report=report.id).all()
                if len(reportStatus) != 0:
                    return jsonify(
                        {'data': '', 'message': "Report status is = '" + reportStatus[0].status + "'", 'error': ''})
                else:
                    return jsonify({'data': '', 'message': "Your report has not any status yet", 'error': ''})
            else:
                return jsonify({'data': '', 'message': '', 'error': 'Invalid reportID'})
        else:
            return jsonify({'data': '', 'message': '', 'error': 'Invalid userID'})

@app.route('/getCrimeAndMissing', methods = ['GET'])
def getCrimeAndMissing():
        allReports = Report.query.filter(or_(Report.rType=='Crime Report' , Report.rType=='Missing Report')).all()
        return jsonify({'data': allReports, 'message': 'Sucessfull', 'error': ''}, )

@app.route('/')
def hello_world():
    return 'Hello Reporting App!'

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error':'Notfound' }),404)


if __name__ == '__main__':
    app.run()
