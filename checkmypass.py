import hashlib
import requests
import sys


def request_api_data(spec_char):
    url = 'https://api.pwnedpasswords.com/range/' + spec_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'error fetching: {res.status_code}.Check the API')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())

    for h, counter in hashes:
        if h == hash_to_check:
            return counter
    return 0


def pwnd_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    response = request_api_data(sha1password[:5])
    return get_password_leaks_count(response, sha1password[5:])


def read_pass_txt(file):
    try:
        txt = open(file, 'r')
        for i in txt.readlines():
            yield i.strip()
    except FileNotFoundError:
        print('Enter the right file name')
    except Exception as err:
        print(f'Couldn`t open the file. Check the error: {err}')


if __name__ == '__main__':

    for i in read_pass_txt(sys.argv[1]):
        if a := pwnd_api_check(i):
            print(f"{i} was found {a} times. Better consider to change your password")
        else:
            print(f'your password ({i}) is secure for now')
