import pandas as pd
from nfstream import NFStreamer, NFPlugin
from nfstream.flow import NFlow
import os
import seaborn as sns
import pandas as pd
from nfstream import NFStreamer, NFPlugin
from nfstream.flow import NFlow
import os
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import torch.nn as nn

# Getting data from pcap files
path = os.path.dirname(os.path.realpath(__file__)) + '/../datasets/' 
filename = 'capture-18-12-520k.pcapng'
# filename = 'network-wide-normal-14.pcap'
# filename = 'gb-communication.pcapng'
# normal_flows = NFStreamer(source = path + filename, statistical_analysis=True)
# normal_flows.to_csv()
# df = pd.read_csv(path + filename + '.csv', low_memory=False)

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
            splitted = X_tmp[column].str.split('.', expand = True).astype(int)
            splitted.columns = new_names
            cols.append(new_names)
    
            X_tmp = pd.concat([X_tmp, splitted], axis = 1)
        X_tmp.drop(columns = self.column_names, inplace = True)
        return X_tmp
#%%


# def generate_dataset(filename):
#     path = os.path.dirname(os.path.realpath(__file__)) + '/../datasets/' 
#     normal_flows = NFStreamer(source = path + filename, statistical_analysis=True)
#     normal_flows.to_csv()
#     df = pd.read_csv(path + filename + '.csv', low_memory=False)
#     data = df[df['ip_version'] == 4]
#     data = data.drop(columns=['src_oui', 'ip_version', 'dst_oui', 'application_name', 'application_category_name', 'vlan_id', 'expiration_id', 'content_type', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'requested_server_name', 'src_mac', 'dst_mac', 'application_is_guessed', 'application_confidence', 'tunnel_id', 'id'])

#     return data

# def preprocess(data):
#     categorical_columns = ['src_ip_' + str(i) for i in range(4)]
#     categorical_columns.extend(['dst_ip_' + str(i) for i in range(4)])
#     categorical_columns.extend(['protocol'])
#     columns_to_scale = data.columns[data.columns.map(lambda x: x not in categorical_columns and x not in ['src_ip', 'dst_ip'])]

#     ct = ColumnTransformer([
#             ('scaler', StandardScaler(), columns_to_scale)
#         ], remainder='passthrough')
#     ip_encoder = IpEncoder(['src_ip', 'dst_ip'])
#     ip_encoder.fit(data)
#     df = ip_encoder.transform(data)
#     columns = df.columns
#     df = ct.fit_transform(df)
#     # df = pd.DataFrame(df, columns = columns)
    
    
    
#     # pipeline = Pipeline(steps= [
#     #     ('ip_encoder', IpEncoder(['src_ip', 'dst_ip'])),
#     #     ('scaler', ct)
#     # ])
#     # pipeline.fit(data)
#     # scaled_features = pipeline.transform(data)
#     # df = pd.DataFrame(scaled_features, columns=data.columns)
#     return df
# df = generate_dataset(filename)
# X_transformed = preprocess(df)
# df = torch.tensor(X_transformed)
# seq_len, n_features = df.shape[0], df.shape[1]
#%% CREATE DATASET WITH PYTORCH
import torchvision
from torch.utils.data import Dataset, DataLoader

class FlowDataset(Dataset):
  def __init__(self, filename, transforms = None):
    self.streamer = NFStreamer(source = filename, statistical_analysis=True)
    # self.streamer.to_csv()
    self.flows = self.streamer.to_pandas()
    self.flows = self.flows[self.flows['ip_version'] == 4]
    self.flows = self.flows.drop(columns=['src_oui', 'ip_version', 'dst_oui', 'application_name', 'application_category_name', 'vlan_id', 'expiration_id', 'content_type', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'requested_server_name', 'src_mac', 'dst_mac', 'application_is_guessed', 'application_confidence', 'tunnel_id', 'id'])
    categorical_columns = ['src_ip_' + str(i) for i in range(4)]
    categorical_columns.extend(['dst_ip_' + str(i) for i in range(4)])
    categorical_columns.extend(['protocol'])
    columns_to_scale = self.flows.columns[self.flows.columns.map(lambda x: x not in categorical_columns and x not in ['src_ip', 'dst_ip'])]
    ct = ColumnTransformer([
            ('scaler', StandardScaler(), columns_to_scale)
        ], remainder='passthrough')
    ip_encoder = IpEncoder(['src_ip', 'dst_ip'])
    pipeline = Pipeline(steps= [
        ('ip_encoder', IpEncoder(['src_ip', 'dst_ip'])),
        ('scaler', ct)
    ])
    self.transforms = transforms
    pipeline.fit(self.flows)
    self.flows = pipeline.transform(self.flows)
    self.flows = [torch.tensor(f).unsqueeze(1).float() for f in self.flows]

  def __getitem__(self, idx):
    return self.flows[idx]

  def __len__(self):
    return len(self.flows)


filename = 'capture-18-12-520k.pcapng'
transf = torchvision.transforms.Compose(
    [
        torchvision.transforms.ToTensor()
    ]
)
df = FlowDataset(path + filename)
#%% DATAlOADER
# dataloader = DataLoader(df, batch_size=32, shuffle=True)
#%%
class Encoder(nn.Module):

  def __init__(self, seq_len, n_features, embedding_dim=64):
    super(Encoder, self).__init__()

    self.seq_len, self.n_features = seq_len, n_features
    self.embedding_dim, self.hidden_dim = embedding_dim, 2 * embedding_dim

    self.rnn1 = nn.LSTM(
      input_size=n_features,
      hidden_size=self.hidden_dim,
      num_layers=1,
      batch_first=True
    )
    
    self.rnn2 = nn.LSTM(
      input_size=self.hidden_dim,
      hidden_size=embedding_dim,
      num_layers=1,
      batch_first=True
    )

  def forward(self, x):
    x = x.reshape((1, self.seq_len, self.n_features))

    x, (_, _) = self.rnn1(x)
    x, (hidden_n, _) = self.rnn2(x)
    return hidden_n.reshape((self.n_features, self.embedding_dim))
#%%
class Decoder(nn.Module):

  def __init__(self, seq_len, input_dim=64, n_features=1):
    super(Decoder, self).__init__()

    self.seq_len, self.input_dim = seq_len, input_dim
    self.hidden_dim, self.n_features = 2 * input_dim, n_features

    self.rnn1 = nn.LSTM(
      input_size=input_dim,
      hidden_size=input_dim,
      num_layers=1,
      batch_first=True
    )

    self.rnn2 = nn.LSTM(
      input_size=input_dim,
      hidden_size=self.hidden_dim,
      num_layers=1,
      batch_first=True
    )

    self.output_layer = nn.Linear(self.hidden_dim, n_features)

  def forward(self, x):
    x = x.repeat(self.seq_len, self.n_features)
    x = x.reshape((self.n_features, self.seq_len, self.input_dim))

    x, (hidden_n, cell_n) = self.rnn1(x)
    x, (hidden_n, cell_n) = self.rnn2(x)
    x = x.reshape((self.seq_len, self.hidden_dim))

    return self.output_layer(x)
#%%
class RecurrentAutoencoder(nn.Module):

  def __init__(self, seq_len, n_features, embedding_dim=64):
    super(RecurrentAutoencoder, self).__init__()

    self.encoder = Encoder(seq_len, n_features, embedding_dim)
    self.decoder = Decoder(seq_len, embedding_dim, n_features)

  def forward(self, x):
    x = self.encoder(x)
    x = self.decoder(x)

    return x
#%%
model = RecurrentAutoencoder(df[0].shape[0], 1, 128)
#%%
import copy
import torch
def train_model(model, train_dataset, val_dataset, n_epochs):
  optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
  criterion = nn.L1Loss(reduction='sum')
  history = dict(train=[], val=[])

  best_model_wts = copy.deepcopy(model.state_dict())
  best_loss = 10000.0
  
  for epoch in range(1, n_epochs + 1):
    model = model.train()

    train_losses = []
    for seq_true in train_dataset:
      optimizer.zero_grad()

      seq_true = seq_true
      seq_pred = model(seq_true)

      loss = criterion(seq_pred, seq_true)

      loss.backward()
      optimizer.step()

      train_losses.append(loss.item())

    val_losses = []
    model = model.eval()
    with torch.no_grad():
      for seq_true in val_dataset:

        seq_true = seq_true
        seq_pred = model(seq_true)

        loss = criterion(seq_pred, seq_true)
        val_losses.append(loss.item())

    train_loss = np.mean(train_losses)
    val_loss = np.mean(val_losses)

    history['train'].append(train_loss)
    history['val'].append(val_loss)

    if val_loss < best_loss:
      best_loss = val_loss
      best_model_wts = copy.deepcopy(model.state_dict())

    print(f'Epoch {epoch}: train loss {train_loss} val loss {val_loss}')

  model.load_state_dict(best_model_wts)
  return model.eval(), history
#%%
model, history = train_model(
  model, 
  df, 
  df, 
  n_epochs=10
)
