# -*- coding: utf-8 -*-
"""
Created on Thu Jul 18 12:42:45 2024

@author: Vivek
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Step 1: Create the CSV File
data = {
    'duration': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    'protocol_type': ['tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp', 'tcp'],
    'service': ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http'],
    'src_bytes': [181, 239, 235, 219, 217, 217, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    'dst_bytes': [5450, 4860, 1337, 1337, 2032, 2032, 2032, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    'flag': ['SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'RSTO', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF', 'SF'],
    'label': ['normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly', 'anomaly']
}

df = pd.DataFrame(data)
df.to_csv('network_traffic_data.csv', index=False)

# Step 2: Data Collection and Preprocessing
data = pd.read_csv('network_traffic_data.csv')

# Separate features and labels
X = data.drop('label', axis=1)
y = data['label']

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 3: Train the Machine Learning Model
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 4: Real-Time Intrusion Detection Function
def detect_intrusion(packet_data):
    packet_data_scaled = scaler.transform(packet_data)
    prediction = model.predict(packet_data_scaled)
    return prediction

# Example packet data (to be replaced with real-time data)
example_packet = np.array([[0.5, 0.2, 0.1, 0.7, 0.4, 0.6]])
print(detect_intrusion(example_packet))

# Snort Integration (to be added to Snort configuration file)
snort_rule = """
alert tcp any any -> any any (msg:"Potential Intrusion Detected"; sid:1000001; content:"|00 11 22 33|"; threshold:type threshold, track by_src, count 1, seconds 60; resp:rst_all; pcre:"/\\x00\\x11\\x22\\x33/"; flow:established,to_server; metadata:service http; reference:url,example.com;)
"""

print(snort_rule)
