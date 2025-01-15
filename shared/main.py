from nfstream import NFPlugin, NFStreamer
from nfstream.flow import NFlow
import torch
import torch.nn as nn
import pandas as pd
import numpy as np
import joblib
#%%
from src.utils import DropExcessCols, MsToSeconds, AppendPayloadDistro, PacketSanitizer
from src.LSTMAE import Encoder, Decoder, LSTMAutoEncoder
class FlowNormalizer():
    def __init__(self, mean = 0., std = 0.5):
        self.mean = mean
        self.std = std
        self.normalizer = torchvision.transforms.Normalize(mean=self.mean, std=self.std)

    def normalize(self, tensor_input):
        return self.normalizer(tensor_input)
    
    def get_mean_std(self):
        return self.mean, self.std
    
labels = {
    'BENIGN': 1,
    'PLAIN_SQL': 2,
    'PLAIN_REDIS': 3,
    'PLAIN_DATA': 4,
    'SQL_INJ': 5,
    'XSS': 6,
    'DDOS': 7,
    'PORTSCAN': 8
}
label_map = {value: key for key, value in labels.items()}
#%%
torch.serialization.add_safe_globals([LSTMAutoEncoder, Encoder, Decoder])
torch.serialization.safe_globals([LSTMAutoEncoder, Encoder, Decoder])
ae_pipeline = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/ae_pipeline.gz')
attack_classifier = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/attack_classifier.gz')
vuln_pipeline = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/vuln_pipeline.gz')
vuln_classifier = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/vuln_classifier.gz')

ae_normalizer = torch.load('/home/grauzone/projects/bakalarka/code/shared/models/ae_normalizer.pth', weights_only=False)
ae = torch.load('/home/grauzone/projects/bakalarka/code/shared/models/flow_final_ae.pth', map_location='cpu', weights_only=False)
ae.device = torch.device("cpu")
ae.encoder.device = torch.device("cpu")
ae.decoder.device = torch.device("cpu")
#%%
import collections
import array
import pandas as pd
source = 'br-fd3c0d98bb1a'
# source = 'br-165ea30f9f63'
to_drop = [
    'bidirectional_first_seen_ms',
    'bidirectional_last_seen_ms',
    'src2dst_first_seen_ms',
    'src2dst_last_seen_ms',
    'dst2src_first_seen_ms',
    'dst2src_last_seen_ms',
    'src_ip', 'dst_ip', 
    'src_port', 'dst_port', 
    'protocol', 'src_oui', 
    'ip_version', 'dst_oui', 
    'application_name', 'application_category_name', 
    'vlan_id', 'expiration_id', 
    'content_type', 'client_fingerprint', 
    'server_fingerprint', 'user_agent', 
    'requested_server_name', 'src_mac', 
    'dst_mac', 'application_is_guessed', 
    'application_confidence', 'tunnel_id', 'id'
]
packets = []
class PayloadCollector(NFPlugin):
    @staticmethod
    def _extend_flow_payload(packet, flow):
        if packet.payload_size > 0:
            payload = packet.ip_packet
            # print(payload)
            flow.udps.payload_encodings.append(payload)
            # print('appended')
            # sanitized_packet = vuln_classifier.transform(payload)
            byte_counter = collections.Counter(payload)
            flow.udps.payload_byte_distro += [byte_counter.get(byte, 0) for byte in range(256)]\
            # pd.concat(flow.udps.flow_payload,

    def on_init(self, packet, flow):
        # print('init')
        flow.udps.payload_byte_distro = np.zeros(256)
        flow.udps.payload_encodings = []
        self._extend_flow_payload(packet, flow)

    def on_update(self, packet, flow):
        # print('Update')
        self._extend_flow_payload(packet, flow)
        # print('after update')
    def on_expire(self, flow):
        # print('expire')
        # flow.udps.payload_encodings = vuln_pipeline.transform(flow.udps.payload_encodings)
        flow.udps.payload_byte_distro = flow.udps.payload_byte_distro/max(1, sum(flow.udps.payload_byte_distro))
    
print('Listening on interface:')
streamer = NFStreamer(source=source, statistical_analysis=True, udps=PayloadCollector(), idle_timeout=10)
classifications = []
statistics = []
print('Distance | Vulnerability | Attack')
for flow in streamer:
    if flow.ip_version == 4:
        
        vulnerability = vuln_pipeline.predict(flow.udps.payload_encodings) if len(flow.udps.payload_encodings) else [0]
        del flow.udps.payload_encodings
        data = list(zip(flow.keys(), flow.values()))
        filtered = {}
        for ix, val in data:
            filtered[ix] = []
            if isinstance(val, array.array) or isinstance(val, np.ndarray):
                filtered[ix].append('[' + ' '.join(map(str, val)) + ']')
            else:
                filtered[ix].append(val)
        data = pd.DataFrame(filtered)
        columns = data.columns
        transformed = ae_pipeline.transform(data)             
        transformed = ae_normalizer.normalize(torch.tensor(np.array(transformed)).unsqueeze(1))
        predictions = ae(transformed.float()).detach()
        error = np.mean(np.square(predictions - transformed)[0][0].numpy())
        print(error)
        distance = np.abs(transformed - predictions)
        # df = pd.DataFrame(distance, columns = columns)
        attack = attack_classifier.predict(distance[0].numpy())
        # classifications.append(c[0])
        vuln_labels = [label_map.get(l, "Unknown") for l in vulnerability]
        attack_label = label_map.get(attack[0])
        statistics.append({'distance': distance[0][0].sum(), 'vuln_analysis': vulnerability, 'attack_analysis': attack})
        print(f'{distance[0][0].sum()} | {" ".join(set(vuln_labels))} | {attack_label}')
        # print(classification[0])
        # print(vulnerability)
        
#%%
with open('test_stats_mg.npy', 'wb') as f:
    np.save(f, statistics)