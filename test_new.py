#-*- coding: utf-8 -*- 

import os

from flask import Flask,render_template,request
from flask.ext.bootstrap import Bootstrap
from yara_collect import submit

app = Flask(__name__)
bootstrap = Bootstrap(app)

@app.route('/', methods = ['GET','POST'])
def index():
	if request.method == 'GET':
		return render_template('input.html')
	if request.method == 'POST':
	    filepath = request.files["filepath"]
	    filepath.save('/root/lsh/1.txt')
	    filedir = '/root/lsh/1.txt'

	    ret = submit(filedir)
	    return render_template('result.html',result=ret)

if __name__ == '__main__':
	app.run(host='172.31.50.43' ,port=8000,debug=True)