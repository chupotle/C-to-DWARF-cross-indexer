import re
import sys
import os
import subprocess
from datetime import datetime

symbolTable = []
addressTable = []
typeTable = []
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

def getTagName(section):
	name = re.split("\n", section)
	for tmp in name:
		if re.search("DW_AT_name", tmp):
			tmp = re.sub(" ", "", tmp)
			tmp = re.split("DW_AT_name", tmp)[1]
			if tmp == "int":
				return "INT"
			if tmp == "char":
				return "CHAR"
			return tmp
	name = "NONE"


def getTagType(section):
	tag = re.split("\n", section)
	for tmp in tag:
		if re.search("DW_TAG", tmp):
			tmp = re.split(" ", tmp)
			for tmp2 in tmp:
				if re.search("DW_TAG", tmp2):
					return tmp2
	tag = "NONE"
	return tag

def getDeclFile(section):
	fileName = re.split("\n", section)
	for tmp in fileName:
		if re.search("DW_AT_decl_file", tmp):
			tmp = re.split(" ", tmp)
			for tok in tmp:
				if re.search("\.c", tok) or re.search("\.h", tok):
					tok = re.split("/", tok)
					for tmp2 in tok:
						if re.search("\.c", tmp2) or re.search("\.h", tmp2):
							return tmp2
	fileName = "NONE"
	return fileName


def getDeclLine(section):
	lineNum = re.split("\n", section)
	for tmp in lineNum:
		if re.search("DW_AT_decl_line", tmp):
			tmp = re.sub(" ", "", tmp)
			return int(re.split("DW_AT_decl_line", tmp)[1], 16)
	lineNum = "0"
	return int(lineNum, 16)


def getLowPc(section):
	low_pc = re.split("\n", section)
	for tmp in low_pc:
		if re.search("DW_AT_low_pc", tmp):
			tmp = re.sub(" ", "", tmp)
			return re.sub("0x", "", re.split("DW_AT_low_pc", tmp)[1])
	low_pc = 0
	return low_pc


def getHighPc(section):
	high_pc = re.split("\n", section)
	for tmp in high_pc:
		if re.search("DW_AT_high_pc", tmp):
			tmp = re.sub(" ", "", tmp)
			return re.split("<.*>", re.split("DW_AT_high_pc", tmp)[1])[1]
	high_pc = 0
	return high_pc


def getType(section):
	var_type = re.split("\n", section)
	for tmp in var_type:
		if re.search("DW_AT_type", tmp):
			tmp = re.sub(" ", "", tmp)
			return re.sub("<0x|>", "", re.split("DW_AT_type", tmp)[1])
	var_type = 0
	return var_type


def getTypeParent(section):
	parent_type = re.split("\n", section)
	for tmp in parent_type:
		if re.search("DW_TAG_structure_type", tmp):
			tmp = re.split("DW_TAG_structure_type", tmp)[0]
			return re.sub(">| ", "", re.sub("\d><0x", "", tmp))
	var_type = 0
	return var_type


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


dwarfdumped = subprocess.check_output(["dwarfdump", sys.argv[1]]).decode('utf-8')
objdumped = subprocess.check_output(['objdump','-d', sys.argv[1]]).decode('utf-8')

raw_dwarf = re.split("\n< ", dwarfdumped)
for chunk in raw_dwarf:
	tag = getTagType(chunk)
	name = getTagName(chunk)
	fileName = getDeclFile(chunk)
	lineNum = getDeclLine(chunk)
	low_pc = getLowPc(chunk)
	high_pc = getHighPc(chunk)
	var_type = ""
	if tag == "DW_TAG_structure_type" or tag == "DW_TAG_union_type":
		var_type = getTypeParent(chunk)
		typeTable.append([name, fileName, lineNum, low_pc, high_pc, var_type])
		symbolTable.append([name, fileName, lineNum, low_pc, high_pc, var_type])
	else:
		var_type = getType(chunk)
		symbolTable.append([name, fileName, lineNum, low_pc, high_pc, var_type])


lineAddr = ""
lineTmp = re.split("\"filepath\"|ET", dwarfdumped)
for line in lineTmp:
	if re.search("0x.*NS uri", line):
		lineAddr = line

lineAddr = re.sub("\n", "", lineAddr)
lineAddr = re.split("0x", lineAddr)
for line in lineAddr:
	address = parseAddressLine(line)
	lineNum = parseLine(line)
	addressTable.append([address, lineNum])
	typeTable.append([fileName, lineNum, low_pc, high_pc, var_type])
i = 0
j = 0
for address in addressTable:
	for sym in symbolTable:
		if sym[3] == address[0]:
			total = int(sym[3], 16) + int(sym[4])
			next_address = hex(total)
			next_address = re.sub("0x", "00", next_address)
			k = 0
			for add in addressTable:
				if add[0] == str(next_address):
					sym[2] = addressTable[k - 1][1]
				k = k + 1
		j = j + 1
	i = i + 1
	j = 0


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
for sourceFiles in sourceFiles:
	with open(sourceFiles[0], 'r') as source:
		target.write("<a name=\"" + str(lineNum) + "\"></a>")
		for line in source.readlines():
			line = cleanLine(line, lineNum, sourceFiles)
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
for sym in symbolTable:
	if sym[0] == "main":
		indexPage.write("<a href=\"" + "assembly.html#" + str(mainNum) + "\">" + "main" + "</a>")
indexPage.close()
