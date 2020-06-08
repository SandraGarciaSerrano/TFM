#!/usr/bin/env python3

import sys
import dataset
from datafreeze import freeze

# Creates database
db = dataset.connect('sqlite:///TFM.db')

#Creates tables in the database
table_clients = db['clients']

#Creates rows in the table
client1 = dict(client ='10.100.0.11', group='224.0.122.5', source='10.100.0.21', provider=5, priority=10)
client2 = dict(group='224.0.122.5', source='10.100.0.21', provider=5, priority=20)
client3 = dict(client='10.100.0.12', group='224.0.122.5', source='10.100.0.22', provider=6, priority=10)
client4 = dict(client='10.100.0.12', group='224.0.10.10', provider=6, priority=20)
client5 = dict(client='10.100.0.12', group='224.0.10.10', source='10.100.0.21', provider=5, priority=30)
client6 = dict(client='10.100.0.13', source='10.100.0.21', provider=5, priority=20)
client7 = dict(client='10.100.0.13', provider=6, priority=30)
client8 = dict(group='224.0.130.15', source='10.100.0.22', provider=6, priority=40)
client8 = dict(client='10.100.0.14', group='224.0.3.3', source='10.100.0.21', provider=5, priority=10)
client8 = dict(client='10.100.0.14', group='224.0.4.3', provider=6, priority=20)
client9 = dict(client='10.100.0.13', group='224.0.122.5', source='10.100.0.21', provider=5, priority=20)
client10 = dict(client='10.100.0.14', group='224.0.122.5', provider=6, priority=20)
client11 = dict(client='10.100.0.14', group='224.0.122.5', source='10.100.0.21', provider=5, priority=10)
client12 = dict(client='10.100.0.12', group='224.0.10.10', provider=5, priority=20)
table_clients.insert(client1)
table_clients.insert(client2)
table_clients.insert(client3)
table_clients.insert(client4)
table_clients.insert(client5)
table_clients.insert(client6)
table_clients.insert(client7)
table_clients.insert(client8)
table_clients.insert(client9)
table_clients.insert(client10)
table_clients.insert(client11)
table_clients.insert(client12)

#Saves the result in a JSON
result = db['clients'].all()
freeze(result, format='json', filename='clients.json')



	

