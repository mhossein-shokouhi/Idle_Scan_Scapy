from scapy.all import *
import csv, random, argparse, time

parser = argparse.ArgumentParser(description="This code performs the famous idle scan using the Scapy library in Python 3.0. Make sure to run it with root privilages. 1000 most common ports are scanned.",
	epilog="Written by: Mohammad Hossein Shokouhi, shokuhi.mh@gmail.com, https://github.com/mhossein-shokouhi/DL_OD_DE")
parser.add_argument('-p','--port',type=int, help="Zombie port. The default value is 80.")
parser.add_argument('-e','--epoch',type=int, help="Number of times to scan closed ports. The default value is 3.")
parser.add_argument('--maxchecks',type=int, help="Maximum number of times to check the selected ports to determine if they are really open.")
parser.add_argument('--minaccuracy',type=float, help="If a selected port is open at least (minaccuracy * maxchecks) times, it is marked as really open.")
parser.add_argument('zIP',type=str, help="Zombie IP")
parser.add_argument('tIP',type=str, help="Target IP")
args=parser.parse_args()

if args.port:
	zport = args.port
else:
	zport = 80

if args.epoch:
	num_epoch = args.epoch
else:
	num_epoch = 2
	
if args.maxchecks:
	max_checks = args.maxchecks
else:
	max_checks = 10
	
if args.minaccuracy:
	min_accuracy = args.minaccuracy
else:
	min_accuracy = 0.6

L3_norm = IP(dst=args.zIP) # src is your IP and dst is the zombie's IP
L3_fake = IP(src=args.zIP, dst=args.tIP) # src is the zombie's IP and dst is the target's IP

L4_norm = TCP(dport=zport, flags="SA")

with open("TCP_1000.txt", "r") as file:
	csvreader = csv.reader(file)
	for row in csvreader:
		TCP_ports = row
	for i in range(len(TCP_ports)):
		TCP_ports[i] = int(TCP_ports[i])

open_ports = []

s = conf.L3socket()

def port_scanner(ports_list):
	n_ports = len(ports_list)
	results = []
	normp = s.sr1(L3_norm/L4_norm, verbose=False)
	id_before = normp.id

	for p in ports_list:
		L4_fake = TCP(sport=zport, dport=p, flags="S")
		s.send(L3_fake/L4_fake)

	time.sleep(0.05)

	normp2 = s.sr1(L3_norm/L4_norm, verbose=False)
	id_after = normp2.id

	if (id_after - id_before >= 2):
		if(n_ports==1):
			results.extend(ports_list)
		else:
			port_div = int(n_ports/2)
			results1 = port_scanner(ports_list[0:port_div])
			results2 = port_scanner(ports_list[port_div:n_ports])
			results.extend(results1)
			results.extend(results2)

	return results

def workload_divider(ports_list):
	n_ports = len(ports_list)
	op = []
	cp = []
	window_len = 30
	port_pointer = 0
	while(port_pointer < n_ports):
		candid_ports = ports_list[port_pointer:(port_pointer + window_len)]
		tmp_op = port_scanner(candid_ports)
		op.extend(tmp_op)
		for x in tmp_op:
			candid_ports.remove(x)
		cp.extend(candid_ports)
		port_pointer += window_len
		if tmp_op:
			window_len = 30
		else:
			window_len = 100

	return(op, cp)


for e in range(num_epoch):
	random.shuffle(TCP_ports)
	a, b = workload_divider(TCP_ports)
	open_ports.extend(a)
	TCP_ports = b

# Verification Phase
# This part removes any randomness and makes sure that all the selected ports are really open.
checklist = {}

L4_norm = TCP(dport=zport, flags="SA")
normp = sr1(L3_norm/L4_norm, verbose=False)
id_before = normp.id
for p in open_ports:
	checklist[p] = 0
	for c in range(max_checks):
		L4_fake = TCP(sport=zport, dport=p, flags="S")

		send(L3_fake/L4_fake, verbose=False)
		time.sleep(0.05)
		normp2 = sr1(L3_norm/L4_norm, verbose=False)

		id_after = normp2.id

		if (id_after - id_before == 2):
			checklist[p] += 1

		id_before = id_after

open_ports = [p for p in checklist if checklist[p]>= min_accuracy * max_checks]

open_ports.sort()
print("Open Ports: ", open_ports)