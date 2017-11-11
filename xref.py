import re
import sys
import os
import subprocess
from datetime import datetime

symbol_table = []
address_table = []
type_table = []
source_files = []

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
	file_name = re.split("\n", section)
	for tmp in file_name:
		if re.search("DW_AT_decl_file", tmp):
			tmp = re.split(" ", tmp)
			for tok in tmp:
				if re.search("\.c", tok) or re.search("\.h", tok):
					tok = re.split("/", tok)
					for tmp2 in tok:
						if re.search("\.c", tmp2) or re.search("\.h", tmp2):
							return tmp2
	file_name = "NONE"
	return file_name


def getDeclLine(section):
	line_num = re.split("\n", section)
	for tmp in line_num:
		if re.search("DW_AT_decl_line", tmp):
			tmp = re.sub(" ", "", tmp)
			return int(re.split("DW_AT_decl_line", tmp)[1], 16)
	line_num = "0"
	return int(line_num, 16)


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


def linkTokens(line, line_num, file_name):
	tmp = line
	tmp = tmp.replace("(", " ( ")
	tmp = tmp.replace(")", " ) ")
	tmp = tmp.replace("{", " { ")
	tmp = tmp.replace("}", " } ")
	tmp = tmp.replace("\n", "")
	output_line = line
	output_line = convertToHTML(output_line)
	return output_line


dwarfdumped = subprocess.check_output(["./dwarfdump", sys.argv[1]]).decode('utf-8')
objdumped = subprocess.check_output(['objdump','-d', sys.argv[1]]).decode('utf-8')

raw_dwarf = re.split("\n< ", dwarfdumped)
for chunk in raw_dwarf:
	tag = getTagType(chunk)
	name = getTagName(chunk)
	file_name = getDeclFile(chunk)
	line_num = getDeclLine(chunk)
	low_pc = getLowPc(chunk)
	high_pc = getHighPc(chunk)
	var_type = ""
	if tag == "DW_TAG_structure_type" or tag == "DW_TAG_union_type":
		var_type = getTypeParent(chunk)
		type_table.append([name, file_name, line_num, low_pc, high_pc, var_type])
		symbol_table.append([name, file_name, line_num, low_pc, high_pc, var_type])
	else:
		var_type = getType(chunk)
		symbol_table.append([name, file_name, line_num, low_pc, high_pc, var_type])


line_addresses = ""
line_tmp = re.split("\"filepath\"|ET", dwarfdumped)
for line in line_tmp:
	if re.search("0x.*NS uri", line):
		line_addresses = line

line_addresses = re.sub("\n", "", line_addresses)
line_addresses = re.split("0x", line_addresses)
for line in line_addresses:
	address = parseAddressLine(line)
	line_num = parseLine(line)
	address_table.append([address, line_num])

	type_table.append([file_name, line_num, low_pc, high_pc, var_type])
index_i = 0
index_j = 0
for address in address_table:
	for sym in symbol_table:
		if sym[3] == address[0]:
			total = int(sym[3], 16) + int(sym[4])
			next_address = hex(total)
			next_address = re.sub("0x", "00", next_address)
			index_k = 0
			for add in address_table:
				if add[0] == str(next_address):
					sym[2] = address_table[index_k - 1][1]
				index_k = index_k + 1
		index_j = index_j + 1
	index_i = index_i + 1
	index_j = 0


file_tmp = dwarfdumped.split("\n")
for line in file_tmp:
	if re.search("NS uri:", line):
		tmp = re.split("0x|  \[", line)
		pc = tmp[1]
		tmp = re.split("\"", tmp[2])
		tmp = re.split("/", tmp[1])
		for tok in tmp:
			if re.search("\.c", tok) or re.search("\.h", tok):
				source_files.append([tok, pc])


for sym in symbol_table:
	print(sym)

line_num = 1
target = open("html/assembly.html", 'w')
target.write("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body><pre>")
main_num = 0
for source_path in source_files:
	with open(source_path[0], 'r') as source:
		target.write("<a name=\"" + str(line_num) + "\"></a>")
		for line in source.readlines():
			line = linkTokens(line, line_num, source_path)
			line_num = line_num + 1
			if re.search("main", line):
				main_num=line_num
			target.write(line + "<a name=\"" + str(line_num) + "\"></a>")
		source.close()

objdumpline = re.split("\n< ", objdumped)
for linee in objdumpline:
	target.write(linee + "<a name=\"" + str(line_num) + "\"></a>")
target.write("</pre></body></html>")
target.close()

index_page = open("html/index.html", 'w')
index_i = 0
index_page.write("<html>")
index_page.write("<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body>")
index_page.write(os.getcwd() + "<br>")
index_page.write(str(datetime.now()) + "<br>")
index_page.write("<a href=\"assembly.html\">" + "assembly" + "</a><br>")
for sym in symbol_table:
	if sym[0] == "main":
		index_page.write("<a href=\"" + "assembly.html#" + str(main_num) + "\">" + "main" + "</a>")
index_page.close()
