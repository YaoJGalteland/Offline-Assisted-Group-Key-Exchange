import OAGKE

# OAGKE, Diffie-Hellman-based blinded KEM
# Participant sample = ['Server', 'Isabel', 'Robin', 'Rolf']
# Each participant generates signing and verification keys
pars = {'Server': None, 'Isabel': None, 'Robin': None, 'Rolf': None}
for participant in pars.keys():
    pars[participant] = OAGKE.User(participant)
    pars[participant].generate_dsa_key()

# Isabel plays as an initiator, Robin and Rolf play as responders
# Responder can be multiple or single, we show an example with two responders
initiator = 'Isabel'
responders = ['Robin', 'Rolf']
pid = 'Robin, Rolf'  # partner id

verifytag = True  # to check if all verifications are correct

# Stage 1, key exchange between the server and the initiator.
# Initiator generates nonce
pars[initiator].ephemeral_value()

# Initiator signs data, the data and signature will be sent to the server
data_initiator_to_server = [pars[initiator].ephemeral_public_value, pid]
signature_initiator_to_server = pars[initiator].sign(data_initiator_to_server)

# Server verifies if data and signature are signed by the initiator
if not OAGKE.verify(pars[initiator].verification_key, data_initiator_to_server, signature_initiator_to_server):
    verifytag = False
    print('Verification failed')

# Server generates ephemeral KEM keys
pars['Server'].ephemeral_value()

# Server signs data, the data and signature will be sent to the initiator
data_server_to_initiator = [pars[initiator].ephemeral_public_value, pid, pars['Server'].ephemeral_public_value]
signature_server_to_initiator = pars['Server'].sign(data_server_to_initiator)

# Server computes session id
sid = hash(OAGKE.transfer_to_bytes([initiator, pid, pars[initiator].ephemeral_public_value,
                                    pars['Server'].ephemeral_public_value]))

# Initiator verifies if data and signature are signed by the server
if not OAGKE.verify(pars['Server'].verification_key, data_server_to_initiator, signature_server_to_initiator):
    verifytag = False
    print('Verification failed')

# Initiator computes session id
sid = hash(OAGKE.transfer_to_bytes([initiator, pid, pars[initiator].ephemeral_public_value,
                                    pars['Server'].ephemeral_public_value]))

# Stage 2, the initiator shares key information to the responders
# Initiator computes the shared key
pars[initiator].exchange(pars[initiator].ephemeral_private_value, pars['Server'].ephemeral_public_value, sid)

# Initiator signs data, the data and signature will be sent to the responders
data_initiator_to_responder = [pars[initiator].ephemeral_public_value, pid, pars['Server'].ephemeral_public_value, sid,
                               pars[initiator].key_confirmation]
signature_initiator_to_responder = pars[initiator].sign(data_initiator_to_responder)

# Responders verify if data and signature are signed by the initiator
if not OAGKE.verify(pars[initiator].verification_key, data_initiator_to_responder, signature_initiator_to_responder):
    verifytag = False
    print('Verification failed')

# Stage 3, key exchange between the responders and the server so that the responders can obtain the same derived key as
# the initiator.
# Responders generate blind and unblind keys
for responder in responders:
    pars[responder].ephemeral_value()

# Responders blind the nonce
responser_blinded_key = dict()
for responder in responders:
    responser_blinded_key[responder] = pars[responder].ephemeral_private_value * pars[initiator].ephemeral_public_value

# Responders sign data, the data and signature will be sent to the server
data_responser_to_server = dict()
signature_responser_to_server = dict()
for responder in responders:
    data_responser_to_server[responder] = [responser_blinded_key[responder], sid, pars['Server'].ephemeral_public_value]
    signature_responser_to_server[responder] = pars[responder].sign(data_responser_to_server[responder])

# Server verifies if data and signature are signed by the responders
for responder in responders:
    if not OAGKE.verify(pars[responder].verification_key, data_responser_to_server[responder],
                        signature_responser_to_server[responder]):
        verifytag = False
        print('Verification failed')

# Server computes blinded shared keys
server_blinded_key = dict()
for responder in responders:
    server_blinded_key[responder] = pars['Server'].ephemeral_private_value * responser_blinded_key[responder]

# Server signs data, the data and signature will be sent to the responders
data_server_to_responder = dict()
signature_server_to_responder = dict()
for responder in responders:
    data_server_to_responder[responder] = [server_blinded_key[responder], sid]
    signature_server_to_responder[responder] = pars['Server'].sign(data_server_to_responder[responder])

# Responders verify if data and signature are signed by the server
for responder in responders:
    if not OAGKE.verify(pars['Server'].verification_key, data_server_to_responder[responder],
                        signature_server_to_responder[responder]):
        verifytag = False
        print('Verification failed')

# Responders compute the shared key by using the unblind key
for responder in responders:
    pars[responder].exchange(pars[responder].inverse_ephemeral_private_value, server_blinded_key[responder], sid)

for responder in responders:
    if pars[responder].key_confirmation != pars[initiator].key_confirmation or not verifytag:
        print(responder + ' gets the shared key')
    else:
        print(responder + ' gets the shared key')
