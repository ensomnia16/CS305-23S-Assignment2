import hashlib
import cryptography.fernet as fer
from pkt_analyzer import *

grade = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Define the name of the file to check
saved_file = ''
ans_file = ['PACKET_INFO.txt', 'HTTP_ANS_EN.txt', 'IPv6_ANS_EN.txt', 'TCP_ANS_EN.txt']
ans_hash = ['765598e5aaeee27f0c4f4fac2945a2da45293becb7754f625506bd9014b26505',
            'cfb3b96795b88774a511de9ba173e1f3754821b4e388c23fd76ae7e5abc781a3',
            '160e7596c7dd626ce12d3227e95235dabff12467eee767a389c6a01b6a9536d4',
            'fb8f70233941c9b8493beef4d40a9fcf468940fead722ce862bdce775e9fb272']
functions = [packet_info, http_stream_analyzer, tcp_stream_analyzer, tcp_stream_analyzer]
function_ = ["TCP connection analysis", "HTTP decode", "IPv6 decode", "TCP decode"]
grades = [5, 20, 10, 45]
params_list = [
    ['TCP_PKTS.pcap', saved_file],
    ['HTTP_.pcap', saved_file, "10.25.217.154", "113.246.57.9", 53564],
    ['TCP_PKTS.pcap', saved_file, "2001:da8:201d:1109::1321", "240e:c3:4000:4::dca9:9823", 12703, 443],
    ['TCP_PKTS.pcap', saved_file, "10.26.184.140", "13.107.42.12", 1433, 443]
]

for i in range(4):
    hasher = hashlib.sha256()
    with open(ans_file[i], 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    _hash = hasher.hexdigest()
    if _hash != ans_hash[i]:
        print(f'ANS {ans_file[i]} File Modified! DO NOT CHANGE THE ANSWER FILE! {ans_file[i]}')
        exit(0)

    # Generate the file name based on the hash of "CS305" + time stamp
    timestamp = str(time.time()).encode('utf-8')
    cs305_hash = hashlib.sha256(b'CS305' + timestamp).hexdigest()
    saved_file = f'{cs305_hash[10:20]}.txt'

    # Check if the hash of ans_file is correct
    if _hash == ans_hash[i]:

        params_list[i][1] = saved_file
        functions[i](*params_list[i])
        if i == 0:
            with open(ans_file[i], 'r') as f_ans, open(saved_file, 'r') as f_saved:
                ans_lines = f_ans.readlines()
                saved_lines = f_saved.readlines()
                if ans_lines == saved_lines:
                    print(f'Test passed! {functions[i].__name__}')
                    grade += grades[i]
                else:
                    print('Test failed.')
                if os.path.exists(saved_file):
                    os.remove(saved_file)
            continue
        key = b'CX6KBVL78QLSTfJGN6yeK4gOxp2yeiEecrNiSXv7uD0='
        f = fer.Fernet(key)
        with open(ans_file[i], 'r') as f_ans, open(saved_file, 'r') as f_saved:
            ciphertext = f_ans.read()
            decode_ans = f.decrypt(ciphertext).decode('utf-8')
            ans_lines_all = decode_ans.splitlines()
            ans_lines_raw = ans_lines_all[:min(len(ans_lines_all), 50)]
            ans_lines = [line.strip() for line in ans_lines_raw]
            saved_lines_raw = f_saved.readlines()
            saved_lines = [line.strip() for line in saved_lines_raw[:min(len(saved_lines_raw), 50)]]
            if ans_lines == saved_lines:
                print(f'Test passed! {functions[i].__name__}')
                grade += grades[i]
            else:
                print(f'Test failed, for part {function_[i]}')
    else:
        print('Test failed: hash value is incorrect.')

    if os.path.exists(saved_file):
        os.remove(saved_file)

sid = os.path.basename(__file__)
hasher = hashlib.sha256()
hasher.update(("CS305" + sid.split('.')[0] + str(grade)).encode('utf-8'))
token = hasher.hexdigest()[:6]
print(f'TOKEN:{token} your grade is {grade}')
