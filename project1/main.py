import time, string, cpuinfo
from passlib.hash import md5_crypt
from itertools import product
from multiprocessing import Pool, Manager
from tqdm import tqdm

SOURCE = 'etc_shadow'
TEAM_NUM = 13
PROCESS_COUNT = 8

DICT = string.ascii_lowercase
CHUNK_SIZE = len(DICT) // PROCESS_COUNT

def get_data(file_path, team_num):
    with open(file_path, 'r') as file:
        data = file.readlines()
    for d in data:
        if str(team_num) in d:
            return d.split(':')[1]
    return None

def print_cpu_info():
    print("CPU:", cpuinfo.get_cpu_info()['brand_raw'])
    print("Cores:", cpuinfo.get_cpu_info()['count'])

def benchmark(charspace, hash, length, cap):
    print("Running Benchmark...")
    salt = hash.split("$")[2]
    cnt = 0
    time_start = time.time()
    for password in product(charspace, repeat=length):
        password = ''.join(password)
        md5_crypt.hash(password, salt=salt)
        cnt += 1
        if cnt == cap:
            duration = time.time() - time_start
            print(f"Time taken for first {cnt} passwords: {duration} seconds")
            print(f"Throughput: {cnt / duration} passwords/second")
            return (duration, cnt)

def crack_hash(charspace, hash, length, count, found, *args):
    salt = hash.split("$")[2]
    pid = 0
    if args:
        pid = args[0]
    total_combinations = len(charspace) ** length
    for password in tqdm(product(charspace, repeat=length), total=total_combinations, position=pid, leave=True):
        if found.value:
            return None
        count.value += 1
        password = ''.join(password)
        if md5_crypt.hash(password, salt=salt) == hash:
            found.value = True
            return password, count
    return None

def make_charspace(dictionary, chunk):
    return chunk+dictionary.replace(chunk, '')

def main():
    hash = get_data(SOURCE, TEAM_NUM)
    # hash = "$1$NpHIlYIA$oECko.sRTw1vQsSSTbM3s0" # Password: aaaccc
    chunks = [DICT[i:i + CHUNK_SIZE] for i in range(0, len(DICT), CHUNK_SIZE)]
    charspaces = [make_charspace(DICT, chunk) for chunk in chunks]

    with Manager() as manager:
        count = manager.Value('i', 0)
        found = manager.Value('i', False)
        results = []

        time_start = time.time()
        with Pool(processes=PROCESS_COUNT) as pool:
            for i, charspace in enumerate(charspaces):
                print(f"Starting process {i + 1} with charspace: {charspace}")
                results.append(pool.apply_async(crack_hash, (charspace, hash, 6, count, found, i)))
            
            pool.close()
            pool.join()
        time_end = time.time()

        for result in results:
            if result:
                password, count = result.get()
                if password:
                    print(f"Password found: {password} in {time_end - time_start} seconds")
                    print(f"Tried {count.value} passwords with {PROCESS_COUNT} processes")
                    print_cpu_info()
                    print(f"Throughput: {count.value / (time_end - time_start)} passwords/second")
                    break

if __name__ == "__main__":
    # hash = "$1$NpHIlYIA$oECko.sRTw1vQsSSTbM3s0"
    main()
