"""Source registry. Add a new source by appending an instance to SOURCES."""
from __future__ import annotations

from panoptes.sources.accounts import AccountsSource
from panoptes.sources.base import Context, SearchOptions, Source
from panoptes.sources.breaches import (CombSource, HIBPSource, InfostealerSource, LeakCheckSource, XposedOrNotSource)
from panoptes.sources.company import (CompaniesHouseSource, EDGARSource, GLEIFSource, LittleSisSource,
                                      OpenCorporatesSource, OpenSanctionsSource)
from panoptes.sources.crypto import CryptoWalletSource
from panoptes.sources.darkweb import AhmiaSource, OnionScanSource, OnionSearchSource
from panoptes.sources.deep import AltAccountSource, SiteDiscoverySource, UsernameDomainsSource
from panoptes.sources.domain import DNSSource, RDAPDomainSource, SubdomainSource, WaybackSource, WebsiteSource
from panoptes.sources.email import (EmailBasicsSource, EmailSitesSource, GoogleAccountSource, GravatarSource,
                                    PGPKeySource, RegistrationSource)
from panoptes.sources.files import FileMetadataSource
from panoptes.sources.geo import LocationSource, WigleSource
from panoptes.sources.github import GitHubEmailSource, GitHubProfileSource
from panoptes.sources.harvester import HarvesterSource
from panoptes.sources.images import ImageIntelSource
from panoptes.sources.ip import GeoIPSource, InternetDBSource, RDAPIPSource, ReverseDNSSource
from panoptes.sources.phone import (NameLeadsSource, NameUsernamesSource, NumverifySource, PhoneInfoSource,
                                    PhoneLeadsSource, PhoneRegistrationSource)
from panoptes.sources.platforms import PlatformProfilesSource, ProfileMetadataSource
from panoptes.sources.records import (OffshoreLeaksSource, SexOffenderRegistrySource, USASpendingSource,
                                      USRecordsSource)
from panoptes.sources.recon import DNSBruteSource, LookalikeSource, TLSCertificateSource
from panoptes.sources.social import (InstagramSource, LinkPagesSource, RedditSource, TelegramSource, TikTokSource,
                                     XSource)
from panoptes.sources.threat import DomainReputationSource, IPReputationSource
from panoptes.sources.urls import HistoricalURLSource
from panoptes.sources.emailfind import EmailDiscoverySource
from panoptes.sources.imageanalysis import (AIVisionSource, ImageLocationVerdictSource, ImageTextSource,
                                           VisualGeolocationSource)
from panoptes.sources.profiles import PlatformIntelSource
from panoptes.sources.synthesis import AliasSource, LocationSynthesisSource
from panoptes.sources.websearch import NewsSource, PublicRecordsSource, WebSearchSource

SOURCES: list[Source] = [
    # username
    AccountsSource(), GitHubProfileSource(), PlatformProfilesSource(), XSource(), InstagramSource(), TikTokSource(),
    TelegramSource(), RedditSource(), PlatformIntelSource(), UsernameDomainsSource(), LeakCheckSource(),
    InfostealerSource(), ProfileMetadataSource(), LinkPagesSource(), SiteDiscoverySource(), AltAccountSource(),
    EmailDiscoverySource(), AliasSource(),
    # search engines, news, public records
    WebSearchSource(), NewsSource(), PublicRecordsSource(),
    # email
    EmailBasicsSource(), RegistrationSource(), EmailSitesSource(), GravatarSource(), GoogleAccountSource(),
    GitHubEmailSource(), PGPKeySource(), XposedOrNotSource(), HIBPSource(), CombSource(),
    # phone / name
    PhoneInfoSource(), PhoneRegistrationSource(), NumverifySource(), PhoneLeadsSource(), NameUsernamesSource(),
    NameLeadsSource(),
    # companies & people networks
    SexOffenderRegistrySource(), USRecordsSource(), OffshoreLeaksSource(), USASpendingSource(),
    GLEIFSource(), OpenCorporatesSource(), CompaniesHouseSource(), EDGARSource(), LittleSisSource(), OpenSanctionsSource(),
    # domain
    DNSSource(), RDAPDomainSource(), SubdomainSource(), DNSBruteSource(), TLSCertificateSource(), WebsiteSource(),
    HarvesterSource(), HistoricalURLSource(), LookalikeSource(), DomainReputationSource(), WaybackSource(),
    # ip
    GeoIPSource(), RDAPIPSource(), InternetDBSource(), IPReputationSource(), ReverseDNSSource(),
    # geo / wifi
    LocationSource(), WigleSource(),
    # dark web
    AhmiaSource(), OnionSearchSource(), OnionScanSource(),
    # crypto / files / images
    CryptoWalletSource(), FileMetadataSource(), ImageTextSource(), AIVisionSource(), VisualGeolocationSource(),
    ImageIntelSource(), ImageLocationVerdictSource(),
    # cross-source synthesis
    LocationSynthesisSource(),
]


def sources_for(kind: str) -> list[Source]:
    return [s for s in SOURCES if kind in s.kinds]


def get_source(name: str) -> Source | None:
    return next((s for s in SOURCES if s.name == name), None)


__all__ = ["SOURCES", "Context", "SearchOptions", "Source", "sources_for", "get_source"]
