from passlib.hash import md5_crypt
import itertools as it
import time
import string

TEAM_NUM = 60
count = 0

def get_data(file_path, team_num):
    with open(file_path, 'r') as file:
        data = file.readlines()
    for d in data:
        if str(team_num) in d:
            return d.split(':')[1]
    return None

def benchmark(charspace, hash, length, cap):
    salt = hash.split("$")[2]
    cnt = 0
    time_start = time.time()
    for password in it.product(charspace, repeat=length):
        password = ''.join(password)
        md5_crypt.hash(password, salt=salt)
        cnt += 1
        if cnt == cap:
            duration = time.time() - time_start
            print(f"Time taken for first {cnt} passwords: {duration} seconds")
            return (duration, cnt)

def crack_hash(charspace, hash, length):
    salt = hash.split("$")[2]
    for password in it.product(charspace, repeat=length):
        global count
        count += 1
        password = ''.join(password)
        print(f"Trying password {count}: {password}")
        if md5_crypt.hash(password, salt=salt) == hash:
            print(f"Password found: {password}")
            return password, count
    return None


if __name__ == "__main__":
    hash = get_data('examples/etc_shadow', TEAM_NUM)
    benchmark(charspace=string.ascii_lowercase, hash=hash, length=6, cap=10000)
    # crack_hash(string.ascii_lowercase, hash, 6)
    # print(f"Time taken: {time.time() - start} seconds")
