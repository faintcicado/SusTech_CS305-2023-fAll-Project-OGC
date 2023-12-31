import requests

def testing(num):
    match num:
        case 1:
            headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
            headers={"Authorization": "Basic ZGY6MTIzNA=="}
            q=requests.head('http://localhost:8080/',headers=headers)
            print(q)
        case 2:
            headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
            q = requests.get('http://localhost:8080/', headers=headers)
            print(q)
        #     expecting response: <Response [200]>
        case 3:
            headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
            q = requests.post('http://localhost:8080/', headers=headers)
            print(q)
        #     expecting response: <Response [200]>
        case 4:
            headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
            q = requests.get('http://localhost:8080/')
            print(q)


if __name__ == '__main__':
    print("====================\r\nplease select test num\r\ninput 0 to exit\r\n====================\r\n")
    print()
    while True:
        num = input('=====================\r\n')
        if num == '0':
            break
        else:
            testing(int(num))


