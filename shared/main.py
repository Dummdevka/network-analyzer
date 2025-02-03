from nfstream import NFPlugin, NFStreamer
from nfstream.flow import NFlow
import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator,TransformerMixin
import joblib
#%%
from src.utils import DropExcessCols, MsToSeconds, AppendPayloadDistro, PacketSanitizer
from src.LSTMAE import Encoder, Decoder, LSTMAutoEncoder
from src.LSTMCL import LSTMClassifier
class FlowNormalizer():
    def __init__(self, mean = 0., std = 0.5):
        self.mean = mean
        self.std = std
        self.normalizer = torchvision.transforms.Normalize(mean=self.mean, std=self.std)

    def normalize(self, tensor_input):
        return self.normalizer(tensor_input)
    
    def get_mean_std(self):
        return self.mean, self.std
    
class TimestampsToLog(BaseEstimator, TransformerMixin):
    def __init__(self, column_names):
        self.column_names = column_names
            
    def fit(self, X, y = None):
        return self
    
    def transform(self, X, y = None):
        X_tmp = X.copy()
        cols = X_tmp.columns.to_list()
        
        for column in self.column_names:
            value = X_tmp[column]
            X_tmp[column] = X_tmp[column].apply(lambda x: 1 if x ==1 else (-1 if x ==0 else np.log(x).astype(float)))
        return X_tmp

# Configurations:
# Detect attack/vuln only
# Sensitivity level
# Report susp packets
# Log file path



#%%
torch.serialization.add_safe_globals([LSTMAutoEncoder, Encoder, Decoder])
torch.serialization.safe_globals([LSTMAutoEncoder, Encoder, Decoder])
        
#%%


class CommunicationAnalyzer:
    def __init__(self, attacks_labels, vuln_labels, error_threashold, log_path = 'log.txt', report_susp_flows=True):
        self.attacks_label_map = {value: key for key, value in attacks_labels.items()}
        self.vuln_label_map = {value: key for key, value in vuln_labels.items()}
        self.error_threashold = error_threashold
        self.log_path = log_path
        self.setup()
    def setup(self):
        self.ae_pipeline = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/ae_pipeline_final.gz')
        self.attack_scaler = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/att_scaler_final.gz')
        self.attack_classifier = torch.load('/home/grauzone/projects/bakalarka/code/shared/models/attack_final.pth', map_location='cpu', weights_only=False)
        self.vuln_pipeline = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/vuln_pipeline.gz')
        self.vuln_classifier = joblib.load('/home/grauzone/projects/bakalarka/code/shared/models/vuln_classifier.gz')
        self.ae = torch.load('/home/grauzone/projects/bakalarka/code/shared/models/ae_final.pth', map_location='cpu', weights_only=False)
        self.ae.device = torch.device("cpu")
        self.ae.encoder.device = torch.device("cpu")
        self.ae.decoder.device = torch.device("cpu")
    def get_labels(self, predictions, attack):
        if not attack: 
            return [self.vuln_label_map.get(p, "Unknown") for p in set(predictions)]
        else: 
            return self.attacks_label_map.get(predictions)
    def preprocess(self, flow):
        encodings = flow.udps.payload_encodings
        packets = flow.udps.packets
        del flow.udps.payload_encodings
        del flow.udps.packets
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
        return data, encodings, packets, columns
    def analyze(self, flow):
        data, encodings, packets, columns = self.preprocess(flow)
        ae_predictions, transformed, ae_score = self.get_ae_results(data)
        if (ae_score > self.error_threashold):
            attack_labels = self.get_attack_prediction(packets)
            vuln_labels = self.get_vuln_prediction(encodings)
            self.log_report(flow, ae_score, attack_labels, vuln_labels, encodings)
    def get_ae_results(self, data):
        transformed = self.ae_pipeline.transform(data)             
        transformed = torch.tensor(np.array(transformed)).unsqueeze(1)
        predictions = self.ae(transformed.float()).detach()
        error = np.mean(np.square(predictions - transformed)[0][0].numpy())
        return predictions, transformed, error
    def get_attack_prediction(self, packets):
        packets = self.attack_scaler.transform(np.array(packets))
        oh_predictions = self.attack_classifier(torch.tensor(packets, dtype=torch.float32).unsqueeze(0))
        return self.get_labels(torch.argmax(oh_predictions).item(), True)
    def get_vuln_prediction(self, encodings):
        vulnerabilities = self.vuln_pipeline.predict(encodings) if len(encodings) else [1]
        return self.get_labels(vulnerabilities, False)
    def log_report(self, flow, ae_score, attack, vulnerability, encodings):
        attack_str = ', '.join(attack)
        vuln_str = ', '.join(vulnerability)
        with open(self.log_path, 'a') as file:
            file.write('======\n')
            file.write(f'Suspicious flow detected on port {flow.src_port}, error: {ae_score}\n')
            file.write(f'Attacks: {attack_str}\n')
            file.write(f'Vulnerabilities: {vuln_str}\n')
            file.write(f'Payloads: {encodings}')
            file.write('======\n')
#%%
import collections
import array
import pandas as pd
            
class PayloadCollector(NFPlugin):
    def __init__(self, packet_limit = 15):
        self.packet_limit = packet_limit
        
    def _extend_flow_payload(self, packet, flow):
        payload = packet.ip_packet
        byte_counter = collections.Counter(payload)
        distro = [byte_counter.get(byte, 0) for byte in range(256)]
        if packet.payload_size > 0:
            flow.udps.payload_encodings.append(payload)
            
            flow.udps.payload_byte_distro += distro
        if (len(flow.udps.packets) < self.packet_limit):
            flow.udps.packets.append(self.get_packet(packet)) 
    def get_packet(self, packet):
        byte_counter = collections.Counter(packet.ip_packet)
        distro = [byte_counter.get(byte, 0) for byte in range(256)]
        return distro
    def on_init(self, packet, flow):
        flow.udps.packets = []
        flow.udps.payload_byte_distro = np.zeros(256)
        flow.udps.payload_encodings = []
        self._extend_flow_payload(packet, flow)
    def on_update(self, packet, flow):
        self._extend_flow_payload(packet, flow)
             
    def on_expire(self, flow):
        flow.udps.payload_byte_distro = flow.udps.payload_byte_distro/max(1, sum(flow.udps.payload_byte_distro))
        if (len(flow.udps.packets) < self.packet_limit):
            diff = self.packet_limit - len(flow.udps.packets) 
            for i in range(diff):
                distro = [0 for i in range(256)]
                flow.udps.packets.append(distro)
#%%
import configparser
import os
import sys

class UserCommunicator:
    def __init__(self):
        self.sensitivity_map = {
            'high': 0.1,
            'middle': 0.12,
            'low': 0.16
        }
        self.vulnerabilities = {
            'BENIGN': 1,
            'PLAIN_SQL': 2,
            'PLAIN_REDIS': 3,
            'PLAIN_DATA': 4
        }

        self.attacks = {
            'BENIGN': 0,
            'SQL_INJ': 1,
            'XSS': 2,
            'DDOS': 3,
            'PORTSCAN': 4
        }
        self.config_file = 'config.cfg'
        self.required_config_fields = ['sensitivity', 'interface', 'log_path', 'report_susp_flows', 'idle_timeout']
        self.set_config()
        self.set_analyzer()
    def set_config(self):
        config = configparser.RawConfigParser()

        if not os.path.exists(self.config_file):
            print(f"Error: The configuration file '{self.config_file}' does not exist.")
            sys.exit(1)

        config.read(self.config_file)
            
        self.details_dict = dict(config.items('ANALYZER'))
        for field in self.required_config_fields:
            if not field in self.details_dict:
                print(f'Field {field} is not set in config! Please check your file and try again')
                sys.exit(1)
    def set_analyzer(self):
        self.analyzer = CommunicationAnalyzer(self.attacks, self.vulnerabilities, self.sensitivity_map[self.details_dict['sensitivity']], self.details_dict['log_path'], self.details_dict['report_susp_flows'])
    def analyze(self):
        print('Starting listening ...')
        streamer = NFStreamer(source=self.details_dict['interface'], statistical_analysis=True, udps=PayloadCollector(), idle_timeout=int(self.details_dict['idle_timeout']))
        for flow in streamer:
            self.analyzer.analyze(flow)
        
#%%
communicator = UserCommunicator()
communicator.analyze()