from telnetlib import TLS
import redis

r = redis.StrictRedis(
    host='ec2-35-173-162-204.compute-1.amazonaws.com',
    port=12500, 
    password='p8de3b1b0c088d68499216be1a318a1b3b94a3d5602590544a835a2a8547eed61',
    TLS=True)




# open a connection to Redis
...
 
r.set('foo', 'bar')
value = r.get('foo')
print(value)

