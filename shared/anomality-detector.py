import pandas as pd
from nfstream import NFStreamer, NFPlugin
from nfstream.flow import NFlow
import os
import seaborn as sns

# Getting data from pcap files
path = os.path.dirname(os.path.realpath(__file__)) + '/../datasets/' 
filename = 'capture-18-12-520k.pcapng'
# filename = 'network-wide-normal-14.pcap'
# filename = 'gb-communication.pcapng'
normal_flows = NFStreamer(source = path + filename, statistical_analysis=True)
normal_flows.to_csv()
df = pd.read_csv(path + filename + '.csv', low_memory=False)
#%%

sns.set_theme(palette="mako")

fig = sns.scatterplot(x=df['src2dst_bytes'], y=df['dst2src_bytes'])
fig.set(xlabel="Sent bytes", ylabel="Recived bytes")
#%%
fig = sns.scatterplot(x=df['src2dst_packets'], y=df['dst2src_packets'])
fig.set(xlabel="Sent packets", ylabel="Recived packets")
#%%
fig = sns.scatterplot(x=df['bidirectional_duration_ms'], y=df['bidirectional_bytes'])
fig.set(xlabel="Duration", ylabel="Sent bytes")
#%%
fig = sns.scatterplot(x=df['src2dst_first_seen_ms'], y=df['dst2src_first_seen_ms'])
fig.set(xlabel="Request first seen", ylabel="Response first seen")
#%%
data = df.drop(columns=['src_oui', 'dst_oui', 'application_name', 'application_category_name', 'vlan_id', 'expiration_id', 'content_type', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'requested_server_name', 'src_mac', 'dst_mac', 'application_is_guessed', 'application_confidence', 'tunnel_id', 'id'])
data = data[data['ip_version'] == 4]
#%%
# Plot with TSNE to find patterns
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
def plot_tsne(data):
    pca = PCA(n_components=50)
    data_sampled = data.sample(2400) if len(data) > 2400 else data
    X_reduced = pca.fit_transform(data_sampled)
    tsne = TSNE(n_components=2)
    X_modified = tsne.fit_transform(X_reduced)
    df_modified = pd.DataFrame(X_modified)
    sns.scatterplot(x = df_modified[0], y = df_modified[1])
    
plot_tsne(X_processed)
#%%
sns.set_theme()
sns.lineplot(data, y = 'src2dst_bytes', x = 'bidirectional_first_seen_ms')
#%%
from sklearn.model_selection import train_test_split
# Split dataset
X_train, X_test = train_test_split(data, train_size=0.7, shuffle=True)
#%%
def plot_normalization(data):
    g = sns.PairGrid(data.sample(600))
    g.map_diag(sns.kdeplot)
    g.map_offdiag(sns.kdeplot)
    
plot_normalization(X_train[])
#%% Data preprocessing
from sklearn.base import BaseEstimator,TransformerMixin

# Split IP into 4 features
class IpEncoder(BaseEstimator, TransformerMixin):
    def __init__(self, column_names):
        self.column_names = column_names
            
    def fit(self, X, y = None):
        return self
    
    def transform(self, X, y = None):
        X_tmp = X.copy()
        cols = X_tmp.columns.to_list()
        
        for column in self.column_names:
            new_names = [column + '_' + str(i) for i in range(4)]
            splitted = data[column].str.split('.', expand = True).astype(int)
            splitted.columns = new_names
            cols.append(new_names)
    
            X_tmp = pd.concat([X_tmp, splitted], axis = 1)
        X_tmp.drop(columns = self.column_names, inplace = True)
        return X_tmp
#%%
import pandas as pd
from nfstream import NFStreamer, NFPlugin
from nfstream.flow import NFlow
import os
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

def generate_dataset(filename):
    path = os.path.dirname(os.path.realpath(__file__)) + '/../datasets/' 
    normal_flows = NFStreamer(source = path + filename, statistical_analysis=True)
    normal_flows.to_csv()
    df = pd.read_csv(path + filename + '.csv', low_memory=False)
    categorical_columns = ['src_ip_' + str(i) for i in range(4)]
    categorical_columns.extend(['dst_ip_' + str(i) for i in range(4)])
    categorical_columns.extend(['protocol', 'src_port', 'dst_port'])
    columns_to_scale = data.columns[data.columns.map(lambda x: x not in categorical_columns and x not in ['src_ip', 'dst_ip'])]

    ct = ColumnTransformer([
            ('scaler', StandardScaler(), columns_to_scale)
        ], remainder='passthrough')
    pipeline = Pipeline(steps= [
        ('ip_encoder', IpEncoder(['src_ip', 'dst_ip'])),
        ('scaler', ct)
    ])
    pipeline.fit(data)
    return pipeline.transform(data)



X_transformed = generate_dataset(filename)

#%%

import torch
import torch.nn as nn
import torch.nn.functional as F
#%%

import lightning as L
from torch.utils.data import TensorDataset, DataLoader

class LSTMCustom(L.LoghtningModule):
    def __init__(self):
        super().__init__()
        mean = torch.tensor

    def lstm_unit(self, input_value, long_memory, short_memory):
