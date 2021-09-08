import json
import uuid

from allauth.account.utils import perform_login
from allauth.account.models import EmailAddress
from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialLogin, SocialAccount
from django.contrib.auth import logout
from django.core.exceptions import ValidationError
from django.urls import reverse
from oauth2_provider.models import AccessToken
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_204_NO_CONTENT, HTTP_403_FORBIDDEN
from rest_framework.views import APIView

from badgeuser.authcode import authcode_for_accesstoken
from badgeuser.models import TermsAgreement, StudentAffiliation, Terms, BadgeUser, TermsUrl
from badgrsocialauth.permissions import IsSocialAccountOwner
from badgrsocialauth.serializers import BadgrSocialAccountSerializerV1
from badgrsocialauth.utils import set_session_badgr_app
from django.http import Http404, HttpResponseRedirect
from entity.api import BaseEntityListView, BaseEntityDetailView
from institution.models import Institution
from issuer.permissions import BadgrOAuthTokenHasScope
from mainsite.exceptions import BadgrApiException400
from mainsite.permissions import AuthenticatedWithVerifiedEmail
from mainsite.models import BadgrApp
from mainsite.utils import OriginSetting
from staff.models import InstitutionStaff



class BadgrSocialAccountList(BaseEntityListView):
    model = SocialAccount
    v1_serializer_class = BadgrSocialAccountSerializerV1
    v2_serializer_class = None
    permission_classes = (AuthenticatedWithVerifiedEmail,)

    def get_objects(self, request, **kwargs):
        obj =  self.request.user.socialaccount_set.all()
        return obj

    def get(self, request, **kwargs):
        return super(BadgrSocialAccountList, self).get(request, **kwargs)


class BadgrSocialAccountConnect(APIView):
    permission_classes = (AuthenticatedWithVerifiedEmail, BadgrOAuthTokenHasScope)
    valid_scopes = ['rw:profile']

    def get(self, request, **kwargs):
        if not isinstance(request.auth, AccessToken):
            raise ValidationError("Invalid credentials")
        provider_name = self.request.GET.get('provider', None)
        if provider_name is None:
            raise ValidationError('No provider specified')

        authcode = authcode_for_accesstoken(request.auth)

        redirect_url = "{origin}{url}?provider={provider}&authCode={code}".format(
            origin=OriginSetting.HTTP,
            url=reverse('socialaccount_login'),
            provider=provider_name,
            code=authcode)

        return Response(dict(url=redirect_url))

    def post(self, request, **kwargs):
        if request.user.is_authenticated:
            logout(request)
        return Response(status=HTTP_204_NO_CONTENT)


class BadgrSocialAccountDetail(BaseEntityDetailView):
    model = SocialAccount
    v1_serializer_class = BadgrSocialAccountSerializerV1
    v2_serializer_class = None
    permission_classes = (AuthenticatedWithVerifiedEmail, IsSocialAccountOwner)

    def get_object(self, request, **kwargs):
        try:
            return SocialAccount.objects.get(id=kwargs.get('id'))
        except SocialAccount.DoesNotExist:
            raise Http404

    def get(self, request, **kwargs):
        return super(BadgrSocialAccountDetail, self).get(request, **kwargs)

    def delete(self, request, **kwargs):
        social_account = self.get_object(request, **kwargs)

        if not self.has_object_permissions(request, social_account):
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            user_social_accounts = SocialAccount.objects.filter(user=request.user)
            get_adapter().validate_disconnect(social_account, user_social_accounts)
        except ValidationError as e:
            return Response(str(e), status=HTTP_403_FORBIDDEN)

        social_account.delete()

        return Response(status=HTTP_204_NO_CONTENT)


def add_terms_institution(institution):
    formal_badge_terms, _ = Terms.objects.get_or_create(institution=institution, terms_type=Terms.TYPE_FORMAL_BADGE)
    TermsUrl.objects.get_or_create(terms=formal_badge_terms, language=TermsUrl.LANGUAGE_ENGLISH,  excerpt=False,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/formal-edubadges-agreement-en.md")
    TermsUrl.objects.get_or_create(terms=formal_badge_terms, language=TermsUrl.LANGUAGE_DUTCH, excerpt=False,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/formal-edubadges-agreement-nl.md")
    TermsUrl.objects.get_or_create(terms=formal_badge_terms, language=TermsUrl.LANGUAGE_ENGLISH, excerpt=True,
                                   url='https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/formal-edubadges-excerpt-en.md')
    TermsUrl.objects.get_or_create(terms=formal_badge_terms, language=TermsUrl.LANGUAGE_DUTCH, excerpt=True,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/formal-edubadges-excerpt-nl.md")
    informal_badge_terms, _ = Terms.objects.get_or_create(institution=institution, terms_type=Terms.TYPE_INFORMAL_BADGE)
    TermsUrl.objects.get_or_create(terms=informal_badge_terms, language=TermsUrl.LANGUAGE_ENGLISH, excerpt=False,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/informal-edubadges-agreement-en.md")
    TermsUrl.objects.get_or_create(terms=informal_badge_terms, language=TermsUrl.LANGUAGE_DUTCH, excerpt=False,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/informal-edubadges-agreement-nl.md")
    TermsUrl.objects.get_or_create(terms=informal_badge_terms, language=TermsUrl.LANGUAGE_ENGLISH, excerpt=True,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/informal-edubadges-excerpt-en.md")
    TermsUrl.objects.get_or_create(terms=informal_badge_terms, language=TermsUrl.LANGUAGE_DUTCH, excerpt=True,
                                   url="https://raw.githubusercontent.com/edubadges/privacy/master/university-example.org/informal-edubadges-excerpt-nl.md")


def setup_institution(organisation_name):
    try:
        institution = Institution.objects.get(identifier=organisation_name)
    except Institution.DoesNotExist:
        institution = Institution.objects.create(identifier=organisation_name, name_english=organisation_name)
        add_terms_institution(institution)
    return institution


class SamlLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        validated_name = request.headers.get('Displayname-Saml2-String', None)
        first_name = request.headers.get('Givenname-Saml2-String', None)
        last_name = request.headers.get('Sn-Saml2-String', None)
        affiliations = request.headers.get('Edupersonaffiliation-Saml2-String', None)
        edu_person_principal_name = request.headers.get('Edupersonprincipalname-Saml2-String', None)
        email = request.headers.get('Mail-Saml2-String', None)
        organisation = request.headers.get('O-Saml2-String', None)
        if not all([validated_name, first_name, last_name, affiliations,
                   edu_person_principal_name, email, organisation]):
            raise BadgrApiException400("Login attributes not complete, cannot log in", 999)
        is_teacher = 'staff' in affiliations or 'docent' in affiliations
        institution = setup_institution(organisation)
        try:
            user = BadgeUser.objects.get(username=edu_person_principal_name)
            social_account = user.get_social_account()
        except BadgeUser.DoesNotExist:
            user, _ = BadgeUser.objects.get_or_create(username=edu_person_principal_name, email=email,
                                                      last_name=last_name, first_name=first_name,
                                                      is_teacher=is_teacher, validated_name=validated_name,
                                                      invited=True)
            EmailAddress.objects.create(verified=1, primary=1, email=email, user=user)
            if is_teacher:
                social_account = SocialAccount.objects.create(provider='surf_conext',
                                                              uid=edu_person_principal_name, user=user)
                user.institution = institution
                user.save()
                terms = user.institution.cached_terms()
                for term in terms:
                    terms_agreement, _ = TermsAgreement.objects.get_or_create(user=user, terms=term)
                    terms_agreement.agreed_version = term.version
                    terms_agreement.agreed = True
                    terms_agreement.save()
                InstitutionStaff.objects.create(institution=institution, user=user, **InstitutionStaff.full_permissions())
            else:
                social_account = SocialAccount.objects.create(provider='edu_id',
                                                              uid=edu_person_principal_name, user=user)
                social_account.extra_data = json.dumps({"eduid": str(uuid.uuid4())})
                social_account.save()
                StudentAffiliation.objects.create(user=user, schac_home=organisation, eppn=edu_person_principal_name)
                user.remove_cached_data(['cached_affiliations'])
        sociallogin = SocialLogin(account=social_account, email_addresses=[email for email in user.email_items])
        sociallogin.user = user
        badgr_app = BadgrApp.objects.filter(pk=user.badgrapp_id).first()
        if not badgr_app:
            badgr_app = BadgrApp.objects.all().first()
        set_session_badgr_app(self.request, badgr_app)
        ret = perform_login(self.request, sociallogin.user,
                      email_verification=app_settings.EMAIL_VERIFICATION,
                      redirect_url=sociallogin.get_redirect_url(self.request),
                      signal_kwargs={"sociallogin": sociallogin})
        role = 'teacher' if is_teacher else 'student'
        print(ret.url + f'&role={role}')
        return HttpResponseRedirect(ret.url + f'&role={role}')


