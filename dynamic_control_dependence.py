from collections import deque

filename = 'dotgraph.txt'
with open(filename) as f:
	content = f.readlines()

out_dir = 'outputs'
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

graph_f = {}
graph_b = {}
nodes = []


def write_file(final_string):
	with open("outputs/dyn_control_dep.dot", "w") as text_file:
		text_file.write(final_string)

for i, line in enumerate(content[1:-1]):
	splits = line.split('"')[1::2]
	#print str(i) + " " + line
	#print(splits)
	st = splits[0]
	en = splits[1]
	if not st in graph_f:
		graph_f[st] = []
	if not en in graph_b:
		graph_b[en] = []
	graph_f[st].append(en)
	graph_b[en].append(st)
	nodes.append(st)
	nodes.append(en)

nodes = list(set(nodes))


dyn_cont = {}

string_out = ''
list_out = []

for i, node in enumerate(nodes):
	dyn_cont[node] = []
	cur_node = node
	q = deque() 
	visited = []
	q.append(cur_node)
	visited.append(cur_node)
	if cur_node not in graph_b:
		dyn_cont[cur_node] = 'START'
	else:
		while q:
			cur_node = q.popleft()
			if cur_node != node and cur_node in graph_f:
				if len(graph_f[cur_node]) > 1:
					dyn_cont[node].append(cur_node)
					continue
			if cur_node in graph_b:
				for elem in graph_b[cur_node]:
					if elem not in visited:
						q.append(elem)
						visited.append(elem)
	if len(dyn_cont[node]) == 0:
		dyn_cont[node] = 'START'
	if isinstance(dyn_cont[node], str):
		tmp = '\"' + node + '\" -> \"' + dyn_cont[node] + '\"\n'
		string_out += tmp
		list_out.append(tmp)
	else:
		for elem in dyn_cont[node]:
			tmp = '\"' + node + '\" -> \"' + elem + '\"\n'
			string_out += tmp
			list_out.append(tmp)

list_out.sort()
string_out = "digraph controlflow {\n"
for elem in list_out:
	string_out += elem
string_out += "\n}"
write_file(string_out)
