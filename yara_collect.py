#-*- coding: utf-8 -*- 

from check_yara_format import *


def submit(filedir):
	Yara = check_Yara_Format()
	check_result = []
	filespath = []
	filespath.append(filedir)
	ret = Yara.check_yara_format(filespath)
	if len(ret) == 1:
		if ret[0][0]:
			print "True"
			return True
		else:
			if len(ret[0]) == 4:
				print  "False"+ ' ' +str(ret[0][2])+str(ret[0][1])
				return 0
			elif len(ret[0]) == 3:
				print "False"+ ' ' + str(ret[0][1])
				return False
	else:
		for ret1 in ret:
			if ret1[0]:
				print "True"
				return True
			else:
				if len(ret1) == 4:
					print "False"+str(ret1[2])+str(ret1[1])
					return False
				elif len(ret1) == 3:
					print "False"+str(ret1[1])
					return False
