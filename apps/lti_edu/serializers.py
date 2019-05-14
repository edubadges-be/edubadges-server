from datetime import datetime
from rest_framework import serializers
from issuer.models import BadgeClass, Issuer, BadgeInstance
from lti_edu.models import StudentsEnrolled, BadgeClassLtiContext

from mainsite.drf_fields import ValidImageField


class LTIrequestSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=150, default=1)
    lis_person_name_given = serializers.CharField(max_length=150)
    lis_person_name_family = serializers.CharField(max_length=150)
    lis_person_contact_email_primary = serializers.CharField(max_length=150)
    roles = serializers.ChoiceField(choices=['Instructor', 'Administrator', 'student'])

    tool_consumer_instance_name = serializers.CharField(max_length=150)
    custom_canvas_course_id = serializers.CharField(max_length=150)
    context_title = serializers.CharField(max_length=150)

class BadgeClassSerializer(serializers.ModelSerializer):
    """
    Used by LTI
    """
    class Meta:
        model = BadgeClass
        fields = '__all__'


class BadgeClassLtiContextSerializer(serializers.ModelSerializer):
    badgeClassEntityId = serializers.CharField(source='badge_class.entity_id')
    contextId = serializers.CharField(source='context_id')
    name = serializers.CharField(source='badge_class.name')
    image = ValidImageField(source='badge_class.image')

    class Meta:
        model = BadgeClassLtiContext
        fields = ['badgeClassEntityId','contextId','name','image']

    # def to_representation(self, instance):
    #     data = {
    #         'badgeClassEntityId': instance.badge_class.entity_id,
    #         'contextId': instance.context_id,
    #         'name': instance.badge_class.name,
    #         'image':instance.badge_class.image,
    #     }
    #     return data




class StudentsEnrolledSerializer(serializers.ModelSerializer):
    """
    Used by LTI
    """
    class Meta:
        model = StudentsEnrolled
        fields = '__all__'
        

class IssuerSerializer(serializers.ModelSerializer):

    class Meta:
       model = Issuer
       fields = ('name',)


class BadgeClassSerializerWithRelations(serializers.ModelSerializer):
    issuer = IssuerSerializer()
    
    class Meta:
        model = BadgeClass
        fields = '__all__'


class StudentsEnrolledSerializerWithRelations(serializers.ModelSerializer):
    """
    Serializer of students enrolled with representation of it's relations to badgeclass and issuer
    """
    badge_class = BadgeClassSerializerWithRelations()
    revoked = serializers.SerializerMethodField('get_assertion_revokation')
    
    def get_assertion_revokation(self, enrollment):
        badge_instance = BadgeInstance.objects.filter(entity_id=enrollment.assertion_slug).first()
        if badge_instance:
            return badge_instance.revoked
        else:
            return False
    
    class Meta:
        model = StudentsEnrolled
        fields = '__all__'

    def to_representation(self, instance):
        ret = serializers.ModelSerializer.to_representation(self, instance)
        readable_date = str(datetime.strptime(ret['date_created'], '%Y-%m-%dT%H:%M:%S.%fZ').date())
        ret['date_created'] = readable_date


class LtiClientsSerializer(serializers.ModelSerializer):

    name = serializers.CharField(max_length=512)
    slug = StripTagsCharField(max_length=255, read_only=True, source='entity_id')
    consumer_key = serializers.CharField(max_length=512, read_only=True)
    shared_secret = serializers.CharField(max_length=512, read_only=True)

    class Meta:
        model = LtiClient
        fields = ('name', 'slug', 'consumer_key', 'shared_secret')

    def to_internal_value(self, data):
        internal_value = super(LtiClientsSerializer, self).to_internal_value(data)
        issuer_slug = data.get("issuer_slug")
        issuer = Issuer.objects.get(entity_id=issuer_slug)
        internal_value.update({
            "issuer": issuer
        })
        return internal_value

    def to_representation(self, instance):
        representation = super(LtiClientsSerializer, self).to_representation(instance)
        issuer_slug = ''
        if instance.issuer:
            issuer_slug = instance.issuer.entity_id
        representation['issuer_slug'] = issuer_slug
        return representation

    def update(self, instance, validated_data):
        instance.issuer = validated_data.get('issuer')
        instance.name = validated_data.get('name')
        instance.save()
        return instance

    def create(self, validated_data, **kwargs):
        del validated_data['created_by']
        validated_data['shared_secret'] = get_uuid()
        validated_data['consumer_key'] = get_uuid()
        new_client = LtiClient(**validated_data)
        new_client.save()
        return new_client