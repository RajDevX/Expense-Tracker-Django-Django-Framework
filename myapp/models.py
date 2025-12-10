from django.db import models

class User(models.Model):
    age = models.IntegerField()
    uname = models.CharField(max_length=50, unique=True)
    email = models.EmailField(blank=True, null=True, unique=True)
    upassword = models.CharField(max_length=128)
    mobile = models.CharField(max_length=10)
    address = models.CharField(max_length=50)
    monthly_budget = models.FloatField(default=0)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    reset_token = models.CharField(max_length=64, blank=True, null=True)
    reset_token_created = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "user"

    def __str__(self) -> str:
        return self.uname


class Expence(models.Model):
    time = models.TimeField()
    date = models.DateField()
    remark = models.CharField(max_length=100)
    amount = models.FloatField()
    category = models.CharField(max_length=20)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = "expence"

    def __str__(self) -> str:
        return f"{self.remark} ({self.amount})"


class Income(models.Model):
    time = models.TimeField()
    date = models.DateField()
    remark = models.CharField(max_length=100)
    amount = models.FloatField()
    category = models.CharField(max_length=20)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = "income"

    def __str__(self) -> str:
        return f"{self.remark} ({self.amount})"
    
