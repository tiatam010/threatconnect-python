""" custom """
from threatconnect.Properties.AddressProperties import AddressProperties
from threatconnect.Properties.AddressesProperties import AddressesProperties
from threatconnect.Properties.AdversaryProperties import AdversaryProperties
from threatconnect.Properties.AdversariesProperties import AdversariesProperties
from threatconnect.Properties.AttributesProperties import AttributesProperties
from threatconnect.Properties.DocumentProperties import DocumentProperties
from threatconnect.Properties.DocumentsProperties import DocumentsProperties
from threatconnect.Properties.DnsResolutionProperties import DnsResolutionProperties
from threatconnect.Properties.EmailProperties import EmailProperties
from threatconnect.Properties.EmailsProperties import EmailsProperties
from threatconnect.Properties.EmailAddressProperties import EmailAddressProperties
from threatconnect.Properties.EmailAddressesProperties import EmailAddressesProperties
from threatconnect.Properties.FileOccurrenceProperties import FileOccurrenceProperties
from threatconnect.Properties.FileOccurrencesProperties import FileOccurrencesProperties
from threatconnect.Properties.FileProperties import FileProperties
from threatconnect.Properties.FilesProperties import FilesProperties
from threatconnect.Properties.GroupsProperties import GroupsProperties
from threatconnect.Properties.HostProperties import HostProperties
from threatconnect.Properties.HostsProperties import HostsProperties
from threatconnect.Properties.IncidentProperties import IncidentProperties
from threatconnect.Properties.IncidentsProperties import IncidentsProperties
from threatconnect.Properties.IndicatorProperties import IndicatorProperties
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties
from threatconnect.Properties.OwnersProperties import OwnersProperties
from threatconnect.Properties.SecurityLabelProperties import SecurityLabelProperties
from threatconnect.Properties.SecurityLabelsProperties import SecurityLabelsProperties
from threatconnect.Properties.SignatureProperties import SignatureProperties
from threatconnect.Properties.SignaturesProperties import SignaturesProperties
from threatconnect.Properties.TagProperties import TagProperties
from threatconnect.Properties.TagsProperties import TagsProperties
from threatconnect.Properties.ThreatProperties import ThreatProperties
from threatconnect.Properties.ThreatsProperties import ThreatsProperties
from threatconnect.Properties.UrlProperties import UrlProperties
from threatconnect.Properties.UrlsProperties import UrlsProperties
from threatconnect.Properties.VictimPhoneProperties import VictimPhoneProperties
from threatconnect.Properties.VictimPhonesProperties import VictimPhonesProperties
from threatconnect.Properties.VictimProperties import VictimProperties
from threatconnect.Properties.VictimsProperties import VictimsProperties
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties
from threatconnect.Properties.VictimEmailAddressProperties import VictimEmailAddressProperties
from threatconnect.Properties.VictimEmailAddressesProperties import VictimEmailAddressesProperties
from threatconnect.Properties.VictimNetworkAccountProperties import VictimNetworkAccountProperties
from threatconnect.Properties.VictimNetworkAccountsProperties import VictimNetworkAccountsProperties
from threatconnect.Properties.VictimSocialNetworkProperties import VictimSocialNetworkProperties
from threatconnect.Properties.VictimSocialNetworksProperties import VictimSocialNetworksProperties
from threatconnect.Properties.VictimWebSiteProperties import VictimWebSiteProperties
from threatconnect.Properties.VictimWebSitesProperties import VictimWebSitesProperties

""" third-party """
from enum import Enum


class ResourceProperties(Enum):
    """ """
    ADDRESS = AddressProperties
    ADDRESSES = AddressesProperties
    ADVERSARY = AdversaryProperties
    ADVERSARIES = AdversariesProperties
    ATTRIBUTES = AttributesProperties
    DOCUMENT = DocumentProperties
    DOCUMENTS = DocumentsProperties
    DNS_RESOLUTIONS = DnsResolutionProperties
    EMAIL = EmailProperties
    EMAILS = EmailsProperties
    EMAIL_ADDRESS = EmailAddressProperties
    EMAIL_ADDRESSES = EmailAddressesProperties
    FILE = FileProperties
    FILES = FilesProperties
    FILE_OCCURRENCE = FileOccurrenceProperties
    FILE_OCCURRENCES = FileOccurrencesProperties
    GROUPS = GroupsProperties
    HOST = HostProperties
    HOSTS = HostsProperties
    INCIDENT = IncidentProperties
    INCIDENTS = IncidentsProperties
    INDICATOR = IndicatorProperties
    INDICATORS = IndicatorsProperties
    OWNERS = OwnersProperties
    SECURITY_LABEL = SecurityLabelProperties
    SECURITY_LABELS = SecurityLabelsProperties
    SIGNATURE = SignatureProperties
    SIGNATURES = SignaturesProperties
    TAG = TagProperties
    TAGS = TagsProperties
    THREAT = ThreatProperties
    THREATS = ThreatsProperties
    URL = UrlProperties
    URLS = UrlsProperties
    VICTIM = VictimProperties
    VICTIMS = VictimsProperties
    VICTIM_ASSET = VictimAssetsProperties
    VICTIM_ASSETS = VictimAssetsProperties
    VICTIM_EMAIL_ADDRESS = VictimEmailAddressProperties
    VICTIM_EMAIL_ADDRESSES = VictimEmailAddressesProperties
    VICTIM_NETWORK_ACCOUNT = VictimNetworkAccountProperties
    VICTIM_NETWORK_ACCOUNTS = VictimNetworkAccountsProperties
    VICTIM_PHONE = VictimPhoneProperties
    VICTIM_PHONES = VictimPhonesProperties
    VICTIM_SOCIAL_NETWORK = VictimSocialNetworkProperties
    VICTIM_SOCIAL_NETWORKS = VictimSocialNetworksProperties
    VICTIM_WEBSITE = VictimWebSiteProperties
    VICTIM_WEBSITES = VictimWebSitesProperties
