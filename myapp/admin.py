from django.contrib import admin
from .models import Expence, Income, User
# Register your models here.
admin.site.register(Expence)
admin.site.register(Income)
@admin.register(User) 
# @admin.register(Expence) 
class useradmin(admin.ModelAdmin):
    list_display = ["uname", "email", "age", "mobile", "is_admin", "is_active"]
    list_filter = ["is_admin", "is_active"]
    search_fields = ["uname", "email", "mobile"]
# class Expenceadmin(admin.ModelAdmin):
#     list_display=['time','date','remark','amount','category']
    
