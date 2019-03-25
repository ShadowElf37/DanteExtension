import client
import nexus
import mdns

c = client.Client('emery.hackerman.local', min_osi_layer=3)
dante_test = c.construct_packet('dante.local', 'A')
c.send(dante_test)
r = c.recv()
print(r.raw)