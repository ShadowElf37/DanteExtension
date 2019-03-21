import client
import nexus
import mdns

c = client.Client('emery.hackerman.local')
dante_test = c.construct_packet('dante.local', 'A')
c.send(dante_test)
print(c.recv())