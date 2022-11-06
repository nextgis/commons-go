
import requests


client_id = 'test'
url = 'https://my.nextgis.com/oauth2/token/'
user = 'test.free@test.com'
password = 'test'

print('-- ' + user)

payload = {'grant_type': 'password', 'client_id': client_id, 'username': user, 'password': password, 'scope': 'user_info.read'}
response = requests.post(url, data=payload)

j = response.json()
print(j)

auth_header = f'{j["token_type"]} {j["access_token"]}'

url_user_info = 'https://my.nextgis.com/api/v1/user_info/'
response = requests.get(url_user_info, headers={'Authorization': auth_header})
print(response.status_code)
j = response.json()
print(j)

url_support_info = 'https://my.nextgis.com/api/v1/support_info/'
response = requests.get(url_support_info, headers={'Authorization': auth_header})
print(response.status_code)
j = response.json()
print(j)

url_team_info = 'https://my.nextgis.com/api/v1/team/'
response = requests.get(url_team_info, headers={'Authorization': auth_header})
print(response.status_code)
j = response.json()
print(j)



