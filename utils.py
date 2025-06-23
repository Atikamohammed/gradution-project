import joblib
import numpy as np
import os
import joblib

import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
classifier = joblib.load(os.path.join(BASE_DIR,'static', 'classifier.pkl'))
label_encoder = joblib.load(os.path.join(BASE_DIR, 'static','label_encoder.pkl'))


def simulate_device_traffic(device):
    import random
    # Simulate a random traffic record
    features = np.random.rand(classifier.n_features_in_).reshape(1, -1)
    prediction = classifier.predict(features)
    confidence = classifier.predict_proba(features).max()

    attack_label = label_encoder.inverse_transform(prediction)[0]

    return attack_label, confidence
