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

#%%


class CommunicationAnalyzer:
    def __init__(self, attacks_labels, vuln_labels, error_threashold = 5, config, notifiers = []):
        self.attacks_label_map = {value: key for key, value in attacks_labels.items()}
        self.vuln_label_map = {value: key for key, value in vuln_labels.items()}
        self.error_threashold = error_threashold
        self.notifiers = notifiers
        self.error_log_path = config.get('error_log_path', 'logs/error.log')
        self.report_susp_flows = config.get('report_susp_flows', True)
        self.setup()
    def setup(self):
        self.ae_pipeline = joblib.load('models/ae_pipeline_final.gz')
        self.attack_scaler = joblib.load('models/att_scaler_final.gz')
        self.attack_classifier = torch.load('models/attack_final.pth', map_location='cpu', weights_only=False)
        self.vuln_pipeline = joblib.load('models/vuln_pipeline.gz')
        self.vuln_classifier = joblib.load('models/vuln_classifier.gz')
        self.ae = torch.load('models/ae_final.pth', map_location='cpu', weights_only=False)
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
            attack_label = self.get_attack_prediction(packets)
            vuln_labels = self.get_vuln_prediction(encodings)
            if attack_label != 'BENIGN':
                self.log_report(flow, ae_score, 'attack', attack_label, encodings)
            elif any(item != 'BENIGN' for item in vuln_labels):
                self.log_report(flow, ae_score, 'vulnerability', vuln_labels, encodings)
            else:
                if self.report_susp_flows:
                    self.log_report(flow, ae_score, 'mixed', 'Suspicious flow', encodings)
    def get_ae_results(self, data):
        transformed = self.ae_pipeline.transform(data)             
        transformed = torch.tensor(np.array(transformed)).unsqueeze(1)
        predictions = self.ae(transformed.float()).detach()
        error = np.mean(np.square(predictions - transformed)[0][0].numpy())
        return predictions, transformed, error
    def get_attack_prediction(self, packets):
        packets = self.attack_scaler.transform(np.array(packets))
        oh_predictions = self.attack_classifier(torch.tensor(packets, dtype=torch.float32).unsqueeze(0))
        return self.get_labels(torch.argmax(oh_predictions).item(), attack=True)
    def get_vuln_prediction(self, encodings):
        vulnerabilities = self.vuln_pipeline.predict(encodings) if len(encodings) else [1]
        return self.get_labels(np.unique(vulnerabilities), attack=False)
    def log_report(self, flow, ae_score, event_type, event_name, encodings):
        event = {
            'flow': flow,
            'score': ae_score,
            'type': event_type,
            'name': event_name,
            'payloads': encodings
        }
        for notifier in self.notifiers:
            try:
                notifier.notify(event)  
            except Exception as e:
                self.log_error(error=e)
    def log_error(self, error):
        with open(self.error_log_path, 'a') as file:
            file.write(str(error))
                
      
        
#%%
import collections
import array
            
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
import requests
import json
import urllib

class SplunkNotificator:
    def __init__(self, url, token):
        self.url = url
        self.token = token
    def get_body(self, event):
        flow = event['flow']
        data = {
            "event": {
                "type": str(event['type']),
                "name": str(event['name']),
                "score": str(event['score']),
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "payload": str(event['payloads'])
            },
            "sourcetype": "analyzer"
        }
        return json.dumps(data)
    def notify(self, event):
        body = self.get_body(event)
        headers = {
            'Authorization': 'Splunk ' + self.token    
        }
        response = requests.post(self.url, headers = headers, data = body)
        if response.status_code != 200:
            print(f"Sending to Splunk failed with status code: {response.status_code}")
            print("Response text:", response.text)
            raise urllib.error.HTTPError(response.text)
            
#%%
class LogNotificator:
    def __init__(self, path):
        self.path = path
    def get_body(self, event):
        flow = event['flow']
        body = ''
        body = body + ('======\n')
        body = body +(f'Suspicious flow detected on port {flow.src_port}, error: ' + str(event['score']) + '\n')
        body = body +(str(event['type']) + ': ' + str(event['name']) + ' \n')
        body = body +('======\n')
        return body
    def notify(self, event):
        # print(event)
        body = self.get_body(event)
        with open(self.path, 'a') as file:
            file.write(str(body))
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
        self.required_config_fields = ['interface']
        self.splunk_fields = ['enable', 'url', 'token']
        self.logger_fields = ['enable', 'path']
        self.notifiers = []
        self.set_config()
        self.set_notifiers()
        self.set_analyzer()
    def set_config(self):
        config = configparser.RawConfigParser()

        if not os.path.exists(self.config_file):
            print(f"Error: The configuration file '{self.config_file}' does not exist.")
            sys.exit(1)

        config.read(self.config_file)
            
        self.analyzer_dict = dict(config.items('ANALYZER'))
        self.splunk_dict = dict(config.items('SPLUNK'))
        self.logger_dict = dict(config.items('LOGGER'))

        for field in self.required_config_fields:
            if not field in self.analyzer_dict:
                print(f'Field {field} is not set in ANALYZER config! Please check your file and try again')
                sys.exit(1)
    def set_notifiers(self):
        if 'enable' in self.splunk_dict and self.splunk_dict['enable']:
            for field in self.splunk_fields:
                if not field in self.splunk_dict:
                    print(f'Field {field} is not set in SPLUNK config! Please check your file and try again')
                    sys.exit(1)
            self.notifiers.append(SplunkNotificator(self.splunk_dict['url'], self.splunk_dict['token']))
        if 'enable' in self.logger_dict and self.logger_dict['enable']:
            for field in self.logger_fields:
                if not field in self.logger_dict:
                    print(f'Field {field} is not set in LOGGER config! Please check your file and try again')
                    sys.exit(1)
            self.notifiers.append(LogNotificator(self.logger_dict['path']))
    def get_sensitivity():
        sensitivity = self.analyzer_dict.get('sensitivity', 'middle')
        return self.sensitivity_map.get(sensitivity, 0.12)
    def set_analyzer(self):
        self.analyzer = CommunicationAnalyzer(self.attacks, self.vulnerabilities, self.get_sensitivity(), self.analyzer_dict, self.notifiers, )
    def analyze(self):
        print('Starting listening ...')
        streamer = NFStreamer(source=self.analyzer_dict['interface'], statistical_analysis=True, udps=PayloadCollector(), idle_timeout=int(self.analyzer_dict['idle_timeout']))
        for flow in streamer:
            self.analyzer.analyze(flow)
        
#%%
communicator = UserCommunicator()
communicator.analyze()