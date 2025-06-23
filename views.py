
# myapp/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required, user_passes_test



from django.contrib.auth import logout
from django.shortcuts import redirect
from django.shortcuts import render, redirect
from .models import IoTDevice, AttackLog, Alert
from .utils import classifier, label_encoder
import numpy as np
from datetime import datetime
import random

import pandas as pd
import joblib
from .forms import AlgorithmInputForm
from django.conf import settings
import os

def test_algorithm(request):
    prediction = None
    if request.method == 'POST':
        form = AlgorithmInputForm(request.POST)
        if form.is_valid():
            input_data = form.cleaned_data

            # Debugging: Check if all expected fields are present
            print("Form Data:", input_data)
            rename_map = {
    'Header_Length': 'Header_Length',
    'Protocol_Type': 'Protocol_Type',
    'Time_To_Live': 'Time_To_Live',
    'Rate': 'Rate',
    'fin_flag_number': 'fin_flag_number',
    'syn_flag_number': 'syn_flag_number',
    'rst_flag_number': 'rst_flag_number',
    'psh_flag_number': 'psh_flag_number',
    'ack_flag_number': 'ack_flag_number',
    'ece_flag_number': 'ece_flag_number',
    'cwr_flag_number': 'cwr_flag_number',
    'ack_count': 'ack_count',
    'syn_count': 'syn_count',
    'fin_count': 'fin_count',
    'rst_count': 'rst_count',
    'HTTP': 'HTTP',
    'HTTPS': 'HTTPS',
    'DNS': 'DNS',
    'Telnet': 'Telnet',
    'SMTP': 'SMTP',
    'SSH': 'SSH',
    'IRC': 'IRC',
    'TCP': 'TCP',
    'UDP': 'UDP',
    'DHCP': 'DHCP',
    'ARP': 'ARP',
    'ICMP': 'ICMP',
    'IGMP': 'IGMP',
    'IPv': 'IPv',
    'LLC': 'LLC',
    'Tot_sum': 'Tot sum',
    'Min': 'Min',
    'Max': 'Max',
    'AVG': 'AVG',
    'Std': 'Std',
    'Tot_size': 'Tot size',
    'IAT': 'IAT',
    'Number': 'Number',
    'Variance': 'Variance'
}


            # Ensure input_data has the right feature names
            feature_vector = {rename_map.get(k, k): v for k, v in input_data.items()}


            # Debugging: Check if the feature vector is correct
            print("Feature Vector:", feature_vector)

            # Ensure the correct order of features for model input
            feature_order = ['Header Length', 'Protocol Type', 'Time To Live', 'Rate', 'fin_flag_number', 'syn_flag_number',
                             'rst_flag_number', 'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
                             'ack_count', 'syn_count', 'fin_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP',
                             'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max',
                             'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance']

            # Create DataFrame for prediction
            sample_df = pd.DataFrame([[feature_vector[feat] for feat in feature_order]], columns=feature_order)

            # Load model and encoder
            model_path = os.path.join(settings.BASE_DIR, 'static', 'classifier.pkl')
            encoder_path = os.path.join(settings.BASE_DIR, 'static', 'label_encoder.pkl')
            model = joblib.load(model_path)
            le = joblib.load(encoder_path)

            # Prediction
            pred = model.predict(sample_df)
            prediction = le.inverse_transform(pred)[0]
    else:
        form = AlgorithmInputForm()

    return render(request, 'djangoappiot/algorithm.html', {'form': form, 'prediction': prediction})




def device_status(request):
    devices = IoTDevice.objects.all()
    return render(request, 'djangoappiot/device_status.html', {'devices': devices})

def monitor_devices(request):
    devices = IoTDevice.objects.all()
    for device in devices:
        # Simulate normal or attack traffic periodically
        simulated_attack_label, simulated_confidence = simulate_device_traffic(device)

        # Randomly choose whether a device is under attack
        is_under_attack = random.choice([True, False])

        # Update device status based on simulated traffic
        device.is_under_attack = is_under_attack
        device.predicted_attack = simulated_attack_label if is_under_attack else "Normal"

        device.save()  # Save the updated status in the database

    return render(request, 'djangoappiot/monitor.html', {'devices': devices})

def user_dashboard(request):
    devices = IoTDevice.objects.all()
    alerts = Alert.objects.all()
    return render(request, 'djangoappiot/user_dashboard.html', {'devices': devices, 'alerts': alerts})
def simulate_device_traffic(device):
    import random
    # Simulate normal (benign) traffic or small attack patterns
    features = np.random.rand(classifier.n_features_in_).reshape(1, -1)
    prediction = classifier.predict(features)
    confidence = classifier.predict_proba(features).max()

    attack_label = label_encoder.inverse_transform(prediction)[0]

    return attack_label, confidence

def add_device(request):
    if request.method == 'POST':
        device_name = request.POST['device_name']
        sensor_type = request.POST['sensor_type']
        ip_address = request.POST['ip_address']

        # Simulate initial traffic for the new device
        simulated_attack_label, simulated_confidence = simulate_device_traffic(device_name)

        # Create a new IoT device with initial benign status
        device = IoTDevice.objects.create(
            device_name=device_name,
            sensor_type=sensor_type,
            ip_address=ip_address,
            is_under_attack=False,  # Start with benign traffic
            predicted_attack=simulated_attack_label
        )

        return redirect('user_dashboard')
    return render(request, 'djangoappiot/add_device.html')



def view_logsuser(request):
    logs = AttackLog.objects.all().order_by('-timestamp')
    return render(request, 'djangoappiot/view_logsuser.html', {'logs': logs})


def view_logs(request):
    logs = AttackLog.objects.all().order_by('-timestamp')
    alerts = Alert.objects.all().order_by('-timestamp')
    return render(request, 'djangoappiot/view_logs.html', {'logs': logs, 'alerts': alerts})

def test_panel(request):
    devices = IoTDevice.objects.all()
    return render(request, 'djangoappiot/test_panel.html', {'devices': devices})



def simulate_attack(request):
    if request.method == 'POST':
        device_id = request.POST['device_id']
        attack_type = request.POST['attack_type']
        device = IoTDevice.objects.get(id=device_id)

        # Simulate features based on attack_type
        attack_features = {

     'DDoS': [0, 1, 64, 7564, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 6000, 60, 60, 60, 0, 60, 0.000127, 100, 0],
    'Mirai': [0, 47, 64, 7048, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 59200, 592, 592, 592, 0, 592, 0.00014, 100, 0],
    'BruteForce': [0.00, 6, 3, 4, 3, 2, 0, 0, 1, 0, 11, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
}


        # Get the correct features based on attack type
        features = np.array(attack_features[attack_type]).reshape(1, -1)

        # Make sure to have all 39 features (using zeros or default values for missing ones)
        if features.shape[1] != classifier.n_features_in_:
            missing_features = classifier.n_features_in_ - features.shape[1]
            features = np.hstack([features, np.zeros((1, missing_features))])

        # Predict the attack type using the classifier
        predicted_label = classifier.predict(features)[0]
        predicted_attack = label_encoder.inverse_transform([predicted_label])[0]
        confidence = np.max(classifier.predict_proba(features))

        # Update device status
        device.is_under_attack = True
        device.predicted_attack = predicted_attack
        device.save()

        # Log the attack
        AttackLog.objects.create(device=device, detected_attack=predicted_attack, confidence=confidence)

        # Create alert
        Alert.objects.create(device=device, message=f"{predicted_attack} attack detected with confidence {confidence:.2f}")

        return redirect('admin_dashboard')
    return redirect('test_panel')













def admin_logout(request):
    logout(request)
    return redirect('home')




def home(request):
    return render(request, 'djangoappiot/home.html')

def is_admin(user):
    return user.is_superuser

from django.contrib import messages
def admin_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user and user.is_superuser:
            login(request, user)
            messages.success(request, 'Login successful. Welcome, Admin!')
            return redirect('admin_dashboard')
        else:
            messages.error(request, 'Invalid credentials or not an admin user.')
            return render(request, 'djangoappiot/admin_login.html')
    return render(request, 'djangoappiot/admin_login.html')



@user_passes_test(is_admin)
def admin_dashboard(request):
    return render(request, 'djangoappiot/admin_dashboard.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect('user_dashboard')  # Redirect to dashboard
        else:
            return render(request, 'djangoappiot/user_login.html', {
                'message': 'Invalid username or password.',
                'success': False
            })

    return render(request, 'djangoappiot/user_login.html')
