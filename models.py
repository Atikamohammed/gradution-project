from django.db import models
class IoTDevice(models.Model):
    device_name = models.CharField(max_length=100)
    sensor_type = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    is_under_attack = models.BooleanField(default=False)
    predicted_attack = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.device_name

class AttackLog(models.Model):
    device = models.ForeignKey(IoTDevice, on_delete=models.CASCADE)
    detected_attack = models.CharField(max_length=100)
    confidence = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.device.device_name} - {self.detected_attack}"

class Alert(models.Model):
    device = models.ForeignKey(IoTDevice, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Alert for {self.device.device_name}"
