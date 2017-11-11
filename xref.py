import re
import sys
import os
import subprocess
from datetime import datetime

# Holds all DW_TAG_subprogram, DW_TAG_variable, etc...
symbol_table = []
address_table = []
type_table = []

# Hold source/target code file information
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


def toHTMLPath(path):
	if re.search("\.c", path):
		path = re.sub("\.c", ".html", path)
		return path
	if re.search("\.h", path):
		path = re.sub("\.h", "_header.html", path)
		return path
	return ""


def convertIllegalSymbols(line):
	output = line
	if re.search("<.*?>", output):
		output = re.sub("<", "&lt;", output)
		output = re.sub(">", "&gt;", output)
	if re.search("int ", output):
		output = re.sub("int ", "#INT# ", output)
	if re.search("double ", output):
		output = re.sub("double ", "#DOUBLE# ", output)
	if re.search("long ", output):
		output = re.sub("long ", "#LONG# ", output)
	if re.search("float ", output):
		output = re.sub("float ", "#FLOAT# ", output)
	if re.search("short ", output):
		output = re.sub("short ", "#SHORT# ", output)
	if re.search("char ", output):
		output = re.sub("char ", "#CHAR# ", output)
	if re.search("unsigned ", output):
		output = re.sub("unsigned ", "#UNSIGNED# ", output)
	if re.search("String ", output):
		output = re.sub("String ", "#STRING# ", output)
	return output


def inScope(token, line_num, file_name, symbol, input_line):
	if symbol[0] == "DW_TAG_subprogram":
		if symbol[2] == file_name[0] and symbol[3] == line_num:
			print("DECLARED HERE: ", token, file_name[0], line_num)
			return "NOT IN SCOPE"
		else:
			print("IN SCOPE: ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
			input_line = re.sub(token, token + "</a>", input_line)
			return input_line

	if symbol[0] == "DW_TAG_label":
		if symbol[2] == file_name[0] and symbol[3] == line_num:
			print("DECLARED HERE: ", token, file_name[0], line_num)
			return "NOT IN SCOPE"
		else:
			print("IN SCOPE: ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
			input_line = re.sub(token, token + "</a>", input_line)
			return input_line
	if symbol[0] == "DW_TAG_formal_parameter":
		if symbol[2] == file_name[0] and symbol[3] == line_num:
			print("DECLARED HERE: ", token, file_name[0], line_num)
			return "NOT IN SCOPE"
		else:
			global symbol_table
			start_line = 0
			end_line = 0
			for sym in symbol_table:
				if sym[0] == "DW_TAG_subprogram" and sym[3] == symbol[3] and sym[2] == symbol[2]:
					start_line = sym[3]
					end_line = sym[4]
					break

			if symbol[2] == file_name[0] and line_num >= start_line and line_num <= end_line:
				print("IN SCOPE: ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
				input_line = re.sub(token, "<a href=\"" + toHTMLPath(symbol[2]) + "#" + str(symbol[3]) + "\">" + token + "</a>", input_line)
				return input_line
			return "NOT IN SCOPE"
	if symbol[0] == "DW_TAG_variable":
		if symbol[2] == file_name[0] and symbol[3] == line_num:
			print("DECLARED HERE: ", token, file_name[0], line_num)
			return "NOT IN SCOPE"
		else:
			start_line = 0
			end_line = 0
			for sym in symbol_table:
				if sym[0] == "DW_TAG_subprogram" and sym[3] <= symbol[3] and sym[4] >= str(symbol[3]) and sym[2] == symbol[2]:
					start_line = sym[3]
					end_line = sym[4]
					break

			if symbol[2] == file_name[0] and line_num >= start_line and str(line_num) <= end_line:
				print("IN SCOPE: ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
				input_line = re.sub(token, "<a href=\"" + toHTMLPath(symbol[2]) + "#" + str(symbol[3]) + "\">" + token + "</a>", input_line)
				return input_line

			if start_line == 0 and end_line == 0:  # Global Variable
				print("IN SCOPE (GLOBAL VARIABLE): ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
				input_line = re.sub(token, "<a href=\"" + toHTMLPath(symbol[2]) + "#" + str(symbol[3]) + "\">" + token + "</a>", input_line)
				return input_line
			return "NOT IN SCOPE"
	if symbol[0] == "DW_TAG_structure_type" or symbol[0] == "DW_TAG_union_type" or symbol[0] == "DW_TAG_typedef":
		if symbol[2] == file_name[0] and symbol[3] == line_num:
			print("DECLARED HERE: ", token, file_name[0], line_num)
			return "NOT IN SCOPE"
		else:
			start_line = 0
			end_line = 0
			for sym in symbol_table:
				if sym[0] == "DW_TAG_subprogram" and sym[3] <= symbol[3] and sym[4] >= symbol[3] and sym[2] == symbol[2]:
					start_line = sym[3]
					end_line = sym[4]
					break

			print("START LINE: ", start_line)
			print("END LINE: ", end_line)
			print("CURRENT LINE: ", line_num)
			if symbol[2] == file_name[0] and line_num >= start_line and line_num <= end_line:
				print("IN SCOPE: ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
				input_line = re.sub(token, "<a href=\"" + toHTMLPath(symbol[2]) + "#" + str(symbol[3]) + "\">" + token + "</a>", input_line)
				return input_line

			if start_line == 0 and end_line == 0:  # Global Variable
				print("IN SCOPE (GLOBAL VARIABLE): ", token, file_name[0], line_num, "WITH: ", symbol[1], symbol[2], symbol[3])
				input_line = re.sub(token, "<a href=\"" + toHTMLPath(symbol[2]) + "#" + str(symbol[3]) + "\">" + token + "</a>", input_line)
				return input_line

	return "NOT IN SCOPE"


def tokenUsed(tok, used_tokens):
	for tmp in used_tokens:
		if tok == tmp:
			return True
	return False

# converts all types to HTML and styles them


def convertToHTML(line):
	output = line
	if re.search("#INT# ", output):
		output = re.sub("#INT# ", "<font color=\"blue\">int </font>", output)
	if re.search("#DOUBLE# ", output):
		output = re.sub("#DOUBLE# ", "<font color=\"blue\">double </font>", output)
	if re.search("#LONG# ", output):
		output = re.sub("#LONG# ", "<font color=\"blue\">long </font>", output)
	if re.search("#SHORT# ", output):
		output = re.sub("#SHORT# ", "<font color=\"blue\">short </font>", output)
	if re.search("#FLOAT# ", output):
		output = re.sub("#FLOAT# ", "<font color=\"blue\">float </font>", output)
	if re.search("#CHAR# ", output):
		output = re.sub("#CHAR# ", "<font color=\"blue\">char </font>", output)
	if re.search("#STRING# ", output):
		output = re.sub("#STRING# ", "<font color=\"blue\">String </font>", output)
	if re.search("#UNSIGNED# ", output):
		output = re.sub("#UNSIGNED# ", "<font color=\"blue\">unsigned </font>", output)

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

# returns DW_TAG_subprogram, DW_TAG_variable, etc...


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

# returns name of variable, function, etc...


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
	return name

# gets file variable, function, etc... is defined


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

# gets line num variable, function, etc... is defined


def getDeclLine(section):
	line_num = re.split("\n", section)
	for tmp in line_num:
		if re.search("DW_AT_decl_line", tmp):
			tmp = re.sub(" ", "", tmp)
			return int(re.split("DW_AT_decl_line", tmp)[1], 16)
	line_num = "0"
	return int(line_num, 16)  # converts from base 16 to base 10

# gets DW_AT_low_pc for variable, function, etc...


def getLowPc(section):
	low_pc = re.split("\n", section)
	for tmp in low_pc:
		if re.search("DW_AT_low_pc", tmp):
			tmp = re.sub(" ", "", tmp)
			return re.sub("0x", "", re.split("DW_AT_low_pc", tmp)[1])
	low_pc = 0
	return low_pc

# gets DW_AT_high_pc for variable, function, etc...


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

	tokens = re.split(" |,|;|\t|\*|\+|\-|\-|/|\.\w", tmp)
	output_line = line
	output_line = convertIllegalSymbols(output_line)
	output_line = convertToHTML(output_line)

	return output_line


# Get DWARF data from executable
dwarf_code = subprocess.check_output(["./dwarfdump", sys.argv[1]]).decode('utf-8')


# getting info out of DWARF symbol data
raw_dwarf = re.split("\n< ", dwarf_code)
for section in raw_dwarf:
	print(section)
	tag = getTagType(section)
	name = getTagName(section)
	file_name = getDeclFile(section)
	line_num = getDeclLine(section)
	low_pc = getLowPc(section)
	high_pc = getHighPc(section)
	var_type = ""
	if tag == "DW_TAG_structure_type" or tag == "DW_TAG_union_type":
		var_type = getTypeParent(section)
		type_table.append([tag, name, file_name, line_num, 'END LINE', low_pc, high_pc, var_type])
		symbol_table.append([tag, name, file_name, line_num, 'END LINE', low_pc, high_pc, var_type])
	else:
		var_type = getType(section)
		symbol_table.append([tag, name, file_name, line_num, 'END LINE', low_pc, high_pc, var_type])

# Building address table
line_addresses = ""
line_tmp = re.split("\"filepath\"|ET", dwarf_code)
for line in line_tmp:
	if re.search("0x.*NS uri", line):
		line_addresses = line

line_addresses = re.sub("\n", "", line_addresses)
line_addresses = re.split("0x", line_addresses)
for line in line_addresses:
	address = parseAddressLine(line)
	line_num = parseLine(line)
	address_table.append([address, line_num])

# Connecting the scope to functions in the Symbol Table
index_i = 0
index_j = 0
for address in address_table:
	for sym in symbol_table:
		if sym[5] == address[0]:
			total = int(sym[5], 16) + int(sym[6])
			next_address = hex(total)
			next_address = re.sub("0x", "00", next_address)
			index_k = 0
			for add in address_table:
				if add[0] == str(next_address):
					sym[4] = address_table[index_k - 1][1]
				index_k = index_k + 1
		index_j = index_j + 1
	index_i = index_i + 1
	index_j = 0


# Get Decleration Files
file_tmp = dwarf_code.split("\n")
for line in file_tmp:
	if re.search("NS uri:", line):
		tmp = re.split("0x|  \[", line)
		pc = tmp[1]
		tmp = re.split("\"", tmp[2])
		tmp = re.split("/", tmp[1])
		for tok in tmp:
			if re.search("\.c", tok) or re.search("\.h", tok):
				source_files.append([tok, pc])

# Create Directory to hold .html files
directory = 'HTML'
try:
	sub_directory = os.stat(directory)
except:
	sub_directory = os.mkdir(directory)

for sym in symbol_table:
	print(sym)

line_num = 1
# Copying source code to target files
target = open("HTML/assembly.html", 'w')
target.write("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body><pre>")

for source_path in source_files:
	with open(source_path[0], 'r') as source:
		target.write("<a name=\"" + str(line_num) + "\"></a>")
		for line in source.readlines():
			print(line_num)
			line = linkTokens(line, line_num, source_path)

			line_num = line_num + 1
			target.write(line + "<a name=\"" + str(line_num) + "\"></a>")
		source.close()
target.write("</pre></body></html>")
target.close()

index_page = open("HTML/index.html", 'w')
index_i = 0
index_page.write("<html>")
index_page.write("<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/></head><body>")
index_page.write(os.getcwd() + "<br>")
index_page.write(str(datetime.now()) + "<br>")
index_page.write("<a href=\"assembly.html\">" + "assembly" + "</a><br>")
for sym in symbol_table:
	if sym[0] == "DW_TAG_subprogram" and sym[1] == "main":
		index_page.write("<a href=\"" + "assembly.html#" + str(3) + "\">" + sym[1] + "</a>")
index_page.close()
