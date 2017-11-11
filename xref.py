import re
import sys
import os
import subprocess
from datetime import datetime

sourceFiles = []

def parseAddressLine(line):
	address = re.split("  \[", line)[0]
	return address

def parseLine(line):
	line = re.split("\[|\]", line)
	for tok in line:
		if re.search(",", tok):
			line = re.split(",", tok)[0]
			return int(line)
	return 0

def convertToHTML(line):
	output = line
	if re.search("<.*?>", output):
		output = re.sub("<", "&lt;", output)
		output = re.sub(">", "&gt;", output)
	if re.search("int ", output):
		output = re.sub("int ", "<font color=\"blue\">int </font>", output)
	if re.search("double ", output):
		output = re.sub("double ", "<font color=\"blue\">double </font>", output)
	if re.search("long ", output):
		output = re.sub("long ", "<font color=\"blue\">long </font>", output)
	if re.search("float ", output):
		output = re.sub("float ", "<font color=\"blue\">float </font>", output)
	if re.search("short ", output):
		output = re.sub("short ", "<font color=\"blue\">short </font>", output)
	if re.search("char ", output):
		output = re.sub("char ", "<font color=\"blue\">char </font>", output)
	if re.search("unsigned ", output):
		output = re.sub("unsigned ", "<font color=\"blue\">String </font>", output)
	if re.search("String ", output):
		output = re.sub("String ", "<font color=\"blue\">unsigned </font>", output)
	if re.search("#include ", output):
		output = re.sub("#include ", "#<font color=\"red\">include </font>", output)
	if re.search("\t", output):
		output = re.sub("\t", "&nbsp&nbsp&nbsp&nbsp", output)
	if re.search("goto ", output):
		output = re.sub("goto ", "<font color=\"red\">goto </font>", output)
	if re.search("if ", output):
		output = re.sub("if ", "<font color=\"red\">if </font>", output)
	if re.search("for ", output):
		output = re.sub("for ", "<font color=\"red\">for </font>", output)
	if re.search("while ", output):
		output = re.sub("while ", "<font color=\"red\">while </font>", output)
	if re.search("return ", output):
		output = re.sub("return ", "<font color=\"red\">return </font>", output)
	if re.search("struct ", output):
		output = re.sub("struct ", "<font color=\"blue\">struct </font>", output)
	if re.search("typedef ", output):
		output = re.sub("typedef ", "<font color=\"blue\">typedef </font>", output)
	if re.search("\[", output):
		output = re.sub("\[", "<font color=\"red\">[</font>", output)
	if re.search("\]", output):
		output = re.sub("\]", "<font color=\"red\">]</font>", output)
	return output

def cleanLine(line, lineNum, fileName):
	tmp = line
	tmp = tmp.replace("(", " ( ")
	tmp = tmp.replace(")", " ) ")
	tmp = tmp.replace("{", " { ")
	tmp = tmp.replace("}", " } ")
	tmp = tmp.replace("\n", "")
	output = line
	output = convertToHTML(output)
	return output


dwarfdumped = subprocess.check_output(["./dwarfdump", sys.argv[1]]).decode('utf-8')
objdumped = subprocess.check_output(['objdump','-d', sys.argv[1]]).decode('utf-8')

raw_dwarf = re.split("\n< ", dwarfdumped)


file_tmp = dwarfdumped.split("\n")
for line in file_tmp:
	if re.search("NS uri:", line):
		tmp = re.split("0x|  \[", line)
		pc = tmp[1]
		tmp = re.split("\"", tmp[2])
		tmp = re.split("/", tmp[1])
		for tok in tmp:
			if re.search("\.c", tok) or re.search("\.h", tok):
				sourceFiles.append([tok, pc])

try:
    sub_directory = os.stat('html')
except:
    sub_directory = os.mkdir('html')

lineNum = 1
target = open("html/assembly.html", 'w')
target.write("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body><pre>")
mainNum = 0
for sourceFile in sourceFiles:
	with open(sourceFile[0], 'r') as source:
		target.write("<a name=\"" + str(lineNum) + "\"></a>")
		for line in source.readlines():
			line = cleanLine(line, lineNum, sourceFile)
			lineNum = lineNum + 1
			if re.search("main", line):
				mainNum=lineNum
			target.write(line + "<a name=\"" + str(lineNum) + "\"></a>")
		source.close()

objdumpline = re.split("\n< ", objdumped)
for linee in objdumpline:
	target.write(linee + "<a name=\"" + str(lineNum) + "\"></a>")
target.write("</pre></body></html>")
target.close()

indexPage = open("html/index.html", 'w')
index_i = 0
indexPage.write("<html>")
indexPage.write("<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body>")
indexPage.write(os.getcwd() + "<br>")
indexPage.write(str(datetime.now()) + "<br>")
indexPage.write("<a href=\"assembly.html\">" + "assembly" + "</a><br>")
indexPage.write("<a href=\"" + "assembly.html#" + str(mainNum) + "\">" + "main" + "</a>")
indexPage.close()
