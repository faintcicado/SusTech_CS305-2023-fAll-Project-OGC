from pathlib import Path

import requests

def testing(num):
    if num == 1:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.head('http://localhost:8080/', headers=headers)
        print(f'<Response [200]> expected')
        print(q)
    elif num == 2:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.get('http://localhost:8080/', headers=headers)
        print(f'<Response [200]> expected')
        print(q)
        # expecting response: <Response [200]>
    elif num == 3:
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        q = requests.post('http://localhost:8080/', headers=headers)
        print(f'<Response [405]> expected')
        print(q)
        # expecting response: <Response [200]>
    elif num == 4:
        # 1.1
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        session = requests.Session()
        session.headers.update({'Connection': 'keep-alive'})

        response1 = session.get('http://127.0.0.1:8080', headers=headers)
        response2 = session.get('http://127.0.0.1:8080', headers=headers)
        print('<Response [200]> <Response [200]> expected')

        print(response1)
        print(response2)
    elif num == 5:
        # 1.2
        # 1.1
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        session1 = requests.Session()
        session1.headers.update({'Connection': 'keep-alive'})
        session2 = requests.Session()
        session2.headers.update({'Connection': 'keep-alive'})

        response1 = session1.get('http://127.0.0.1:8080', headers=headers)
        response2 = session2.get('http://127.0.0.1:8080', headers=headers)

        print(response1)
        print(response2)

        print('<Response [200]> <Response [200]> expected')

    elif num == 6:
        # 1.3
        headers1 = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        headers2 = {}
        q = requests.head('http://localhost:8080/', headers=headers1)
        print(q)
        q = requests.head('http://localhost:8080/', headers=headers2)
        print(q)
        print('<Response [200]> <Response [401]> expected')
    elif num == 7:
        # 2
        url1 = 'http://127.0.0.1:8080/?SUSTech-HTTP=1'

        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url=url1, headers=headers)
        print('<Response [200]> [''12589/'', ''a.py'', ''a.txt'', ''client1/'', ''client2/'', ''client3/''] expected')
        print(r)
        print(r.content.decode())
    elif num == 8:
        # 2
        url2 = 'http://127.0.0.1:8080/?SUSTech-HTTP=0'

        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url=url2, headers=headers)
        print('a whole html response expected')
        print(r.content.decode())

    elif num == 9:
        # 2
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url='http://127.0.0.1:8080/a.txt', headers=headers)
        print('sadfsdfasdf expected')
        print(r.content.decode())

    elif num == 10:
        # 3.1
        files = {"firstFile": open('tmp/a.txt', "rb")}

        data = {}
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        print('<Response [200]> <Response [403]> expected')
        r = requests.post(url='http://127.0.0.1:8080/upload?path=client1/', data=data, headers=headers, files=files)
        print(r)
        r = requests.post(url='http://127.0.0.1:8080/upload?path=client2/', data=data, headers=headers, files=files)
        print(r)
    elif num == 11:
        # 3.2
        url = 'http://127.0.0.1:8080/delete?path=client1/a.py'

        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.post(url=url, headers=headers)
        print('<Response [200]> expected')
        print(r)
    elif num == 12:
        # 4
        url = 'http://127.0.0.1:8080/'

        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        print('c20a7336-85da-4604-9885-0e7a17d404e5 <Response [200]> expected c20a7336-85da-4604-9885-0e7a17d404e5')
        r = requests.get(url=url, headers=headers)
        print(r.cookies.values()[0])
        headers = {"Cookie": 'session-id=' + r.cookies.values()[0]}
        q = requests.get('http://localhost:8080/', headers=headers)
        print(q)
        print(q.cookies)
    elif num == 13:
        # 5
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        r = requests.get(url='http://127.0.0.1:8080/client1/a.txt?chunked=1', headers=headers)
        print('<Response [200]> expected')
        print(r)
    elif num == 14:
        # Breakpoint Transmission
        url = 'http://127.0.0.1:8080/client1/a.txt'

        data = {}
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM=",
                   "Range": "0-1,1-2,2-3"}
        r = requests.get(url=url, data=data, headers=headers)
        print('--THISISMYSELFDIFINEDBOUNDARY'
'Content-type= text/plain'
'Content-range= 0-1/11'

'sa'
'--THISISMYSELFDIFINEDBOUNDARY'
'Content-type= text/plain'
'Content-range= 1-2/11'

'ad'
'--THISISMYSELFDIFINEDBOUNDARY'
'Content-type= text/plain'
'Content-range= 2-3/11'

'df'
'--THISISMYSELFDIFINEDBOUNDARY-- expected')
        print(r.content.decode())



if __name__ == '__main__':
    print("====================\r\nplease select test num\r\ninput 0 to exit\r\n====================\r\n")
    print()
    original_list = ['200-1000', '2000-6576', '19000-']
    result_list = [item.split('-') if '-' in item else [item, ''] for item in original_list]
    print(result_list)
    # result = list(map(int, result_list[3]))
    # print(result)


    while True:
        num = input('=====================\r\n')
        if num == '0':
            break
        else:
            testing(int(num))


