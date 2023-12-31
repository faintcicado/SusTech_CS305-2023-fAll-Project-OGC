import requests
headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
q=requests.head('http://localhost:8080/',headers=headers)
print(q)