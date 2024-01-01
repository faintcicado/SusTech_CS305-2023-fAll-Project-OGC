from pathlib import Path

import requests

def testing(num):
    if num == 1:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        headers={"Authorization": "Basic ZGY6MTIzNA=="}
        q = requests.head('http://localhost:8080/', headers=headers)
        print(q)
    elif num == 2:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.get('http://localhost:8080/', headers=headers)
        print(q)
        # expecting response: <Response [200]>
    elif num == 3:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.post('http://localhost:8080/', headers=headers)
        print(q)
        # expecting response: <Response [200]>
    elif num == 4:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.get('http://localhost:8080/')
        print(q)
    elif num == 5:
        url = 'http://localhost:8080/'
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url=url, headers=headers)
        print(r.cookies.values()[0])
        headers = {"Cookie": 'session-id=' + r.cookies.values()[0]}
        q = requests.get('http://localhost:8080/', headers=headers)
        print(q)
        # print(q.cookies)
    elif num == 6:
        # 3.1
        files = {"firstFile": open('tmp/a.txt', "rb")}

        data = {}
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.post(url='http://127.0.0.1:8080/upload?path=client1/', data=data, headers=headers, files=files)
        print(r)
        r = requests.post(url='http://127.0.0.1:8080/upload?path=client2/', data=data, headers=headers, files=files)
        print(r)
    elif num == 7:
        # 3.2
        url = 'http://127.0.0.1:8080/delete?path=client1/a.py'

        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.post(url=url, headers=headers)
        print(r)
    elif num == 8:
        # 2
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url='http://127.0.0.1:8080/a.txt', headers=headers)
        print(r.content.decode())

if __name__ == '__main__':
    print("====================\r\nplease select test num\r\ninput 0 to exit\r\n====================\r\n")
    print()
    path = Path('./data/client1/a.py')
    print(path.exists())

    uri = 'upload?path= /11912113/'
    path = uri.split('=')[1]
    temp = path.split('/', 1)[1]

    while True:
        num = input('=====================\r\n')
        if num == '0':
            break
        else:
            testing(int(num))


