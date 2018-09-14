#!/usr/bin/env python
#coding=utf-8
import sys
import os
import yara
import yaratool
import json
import re
UPLOAD_FILE_PATH = '/home/zhengsai/test_Tornado/upload_sign_web/upload_yarafiles/'
key_threattype =  ['DDOS','RAT','BACKDOOR','APT','DDOS|RAT','RAT|DDOS','EXPLOIT','VIRUS','CONTROL',' ']
behavior_threattype = ['AUTORUN','DELETESELF','FAKE','HIDE','BYPASS','ANTI','EXPLOIT','HIJACK','SPREAD',\
						'INJECT','DDOS','RAT','KEYLOG','PASSSTEAL','RANSOMWARE','BANK','ADWARE','FILE','PROCESS',\
						'REG','NETWORK','MUTEX','SERVICE','PIPE','MEM','MODIFY','GETINFO','GETPRIVILEGE','WINDOW']
class check_Yara_Format():
	def __init__(self):
		pass

	def check_yara_format(self, filespath):
		result_list = []
		for tmp in filespath:
#			filepath = UPLOAD_FILE_PATH + tmp
			filepath = tmp
			check_result = self.check_meta_key(filepath)
			if not check_result[0]:
				result_list.append(check_result)
			else:
				yara_result = self.check_is_yara(filepath)
				if yara_result[0]:
					result_list.append([True, filepath])
				else:
					result_list.append([False, 1002, filepath])

		#else:
			#result_list.append([False, 1001, filepath])

		return result_list

	def check_is_yara(self,filepath):
		try:
			rule = yara.compile(filepath)
			return [True, filepath]
		except Exception,e:
			return [False,1002, filepath]

	def check_meta_key(self,filepath):
		try:
			f = open(filepath,'rb')
			rule = f.read()
			try:
				yr = yaratool.YaraRule(rule)
			except BaseException,e:
				print e
			if not yr.strings:
				return [False, 1004, "yara_strings"]
			if not yr.conditions:
				return [False, 1004, "yara_condition"]
			print len(yr.metas.keys()),"5==="
			if len(yr.metas.keys()) == 10:
				for key in yr.metas.keys():
					if key == "judge":
						if  yr.metas[key][1:-1] == "unknown" or yr.metas[key][1:-1] == "white" or yr.metas[key][1:-1] == "black":
							continue
							
						else:
							return [False, 1003, key,filepath]

					if key == "threatname":
						ret = []
						ret = self.check_threatname(yr.metas,key,filepath)
						if not ret[0]:
							return ret
					
						continue
					
					if key == "threattype":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						if "threatname" not in yr.metas.keys():
							return [False, 1015, key, filepath]
						ret = self.check_threatname(yr.metas,"threatname",filepath)
						if not ret[0]:
							return [False, 1016, key, filepath]
						if '/' in yr.metas["threatname"]:
							if not yr.metas[key][1:-1].upper() in key_threattype:
								return [False, 1005, key, filepath]
							continue
						else:
							if not yr.metas[key][1:-1].upper() in behavior_threattype:
								return [False, 1018, key, filepath]
							continue

					if key == "family":
						if "threatname" not in yr.metas.keys():
							return [False, 1015, key, filepath]
						ret = self.check_threatname(yr.metas,"threatname",filepath)
						if not ret[0]:
							return [False, 1016, key, filepath]
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						if '.' not in yr.metas["threatname"]:
							return [False, 1012, key, filepath]

						if '/' in yr.metas["threatname"]:
							if yr.metas[key][1:-1] != yr.metas["threatname"][1:-1].split('/')[1].split('.')[1]:
								return [False, 1008, key, filepath]
							continue
						else:
							if yr.metas[key][1:-1] != "unknown":
								return [False, 1014, key, filepath]
							continue

					if key == "hacker":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						else:
							continue

					if key == "refer":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						if ',' in yr.metas[key][1:-1]:
							refer_md5 = yr.metas[key][1:-1].split(',')
							for md5 in refer_md5:
								if md5[:4] == "http":
									continue
								elif len(md5) != 32:
									return [False, 1010, key, filepath]
							continue
						else:
							if len(yr.metas[key][1:-1]) != 32:
								return [False, 1010, key,filepath]
						
							continue

					if key == "description":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						else:
							continue

					if key == "comment":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						else:
							continue

					if key == "author":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						else:
							continue

					if key == "date":
						if not yr.metas[key][1:-1]:
							return [False, 1004, key, filepath]
						else:
							continue
					else:
						return [False, 1011, filepath]

				return [True]
			else:
				return[False,1017,filepath]
		except Exception,e:
			print e
			return [False,1020,filepath]
 
	def check_threatname(self,yr_metas,key,filepath):
		if not "threatname" in yr_metas.keys():
			return [False, 1016, key, filepath]
		if not yr_metas[key]:
			return [False, 1004, key, filepath]
		if '.' not in yr_metas[key]:
			return [False, 1009, key, filepath]
		if '/' in yr_metas[key]:
			name_lists = yr_metas[key][1:-1].split('/')
			if len(name_lists[1].split('.')) == 3:
				if not name_lists[1].split('.')[2]:
					return [False, 1021, key, filepath]

			if '[' in name_lists[0]:
				malwaretype = name_lists[0].split('[')[0]
				name_system = name_lists[1].split('.')[0]
				name_threattype = yr_metas[key][1:-1].split(']')[0].split('[')[1]
				if not malwaretype in ['Trojan','Worm','Virus']:
					return [False, 1006, key, filepath]
				if not name_system in ['Linux','Win32','MSIL']:
					return [False, 1007, key, filepath]
				if not name_threattype.upper() in key_threattype:
					return [False, 1005, key, filepath]
			else:
				malwaretype = name_lists[0]
				name_system = name_lists[1].split('.')[0]
				if not malwaretype in ['Trojan','Worm','Virus']:
					return [False, 1006, key, filepath]
				if not name_system in ['Linux','Win32','MSIL']:
					return [False, 1007, key, filepath]
		else:
			threatname_list = yr_metas[key].split('.')
			if len(threatname_list) > 3:
				return [False, 1013, key, filepath]
			else:
				if not yr_metas[key][1:-1].split('.')[0] in behavior_threattype:
					return [False, 1019, key, filepath]
		return [True]

if __name__ == '__main__':
	if len(sys.argv) == 2:
		filepath = sys.argv[1]
#		error_f = open('./errorInfoConfig.json')
#		error_dic = json.load(error_f)
		Yara = check_Yara_Format()
		check_result = []
		filespath = []
		filespath.append(filepath)
#		path = os.path.abspath(filespath)
		ret = Yara.check_yara_format(filespath)
		right_num = 0
		error_num = 0
		if len(ret) == 1:
			if ret[0][0]:
				right_num += 1
#				right_path = os.path.split(ret[0][1])[1]
				print "True"
#				print right_path + " file format is right !!!"
			else:
				if len(ret[0]) == 4:
					error_num += 1
#					error_path = os.path.split(ret[0][3])[1]
					print  "False"+ ' ' +str(ret[0][2])+str(ret[0][1])
#					print  ret[0][2] + ' ' + error_dic[str(ret[0][1])] + ' in ' + error_path
				elif len(ret[0]) == 3:
					error_num += 1
#					error_path = os.path.split(ret[0][2])[1]
					print "False"+ ' ' + str(ret[0][1])
#					print error_dic[str(ret[0][1])] + ' ' + 'error in ' + error_path
		else:
			for ret1 in ret:
				print "==========================================="
				#print ret1
				if ret1[0]:
					right_num += 1
#					right_path = os.path.split(ret1[1])[1]
					#print right_path
#					print right_path + " file format is right !!!"
					print "True"
				else:
					#print ret1
					if len(ret1) == 4:
						error_num += 1
#						error_path = os.path.split(ret1[3])[1]
						print "False"+str(ret1[2])+str(ret1[1])
#						print ret1[2] + ' ' + error_dic[str(ret1[1])] + ' in ' + error_path
					elif len(ret1) == 3:
						error_num += 1
#						error_path = os.path.split(ret1[2])[1]
						print "False"+str(ret1[1])
#						print error_dic[str(ret1[1])] + ' ' + 'error in ' + error_path

		print "file format is right : ",right_num
		print "file format is error : ",error_num