from django.contrib import admin
from ims.models import IMSArchive, LTIApp, LTITenant
from mainsite.admin import badgr_admin


class IMSArchiveAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'created_at', 'metadata_tag')


class LTIAppAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'description', 'privacy_level', 'created_at', 'modified_at')


class LTITenantAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client_key', 'client_secret', 'get_lti_config_url', 'created_at', 'modified_at')
    prepopulated_fields = {'slug': ('organization',)}


badgr_admin.register(IMSArchive, IMSArchiveAdmin)
badgr_admin.register(LTIApp, LTIAppAdmin)
badgr_admin.register(LTITenant, LTITenantAdmin)
