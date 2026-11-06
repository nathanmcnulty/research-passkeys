# Offline fixtures only. The native transport is inspected as source but is
# deliberately NEVER loaded or invoked, even if a Pester mock is absent.
$probeExpectedTuples = @(
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'TenantFormat' }
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'TenantNonzero' }
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'ClientFormat' }
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'ClientNonzero' }
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'UpnLength' }
    @{ Phase = 'Configuration'; Code = 'InvalidConfiguration'; Predicate = 'UpnFormat' }
    @{ Phase = 'Configuration'; Code = 'UnexpectedFailure'; Predicate = 'ConfigurationValidation' }
    @{ Phase = 'Cookie'; Code = 'InvalidCookie'; Predicate = 'CookieName' }
    @{ Phase = 'Cookie'; Code = 'InvalidCookie'; Predicate = 'CookieLength' }
    @{ Phase = 'Cookie'; Code = 'InvalidCookie'; Predicate = 'CookieAlphabet' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseStatus' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseMediaType' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseLocations' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonParse' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonRootObject' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertySetConstruction' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertiesRead' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertyUnique' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion' }
    @{ Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonDispose' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'IssuerMetadataString' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'IssuerMetadataMatch' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'AuthorizationMetadataString' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'AuthorizationMetadataMatch' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'TokenMetadataString' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'TokenMetadataMatch' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'UserInfoMetadataString' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Predicate = 'UserInfoMetadataMatch' }
    @{ Phase = 'AuthorizationResponse'; Code = 'InvalidAuthorizationResponse'; Predicate = 'AuthorizationStatus' }
    @{ Phase = 'AuthorizationResponse'; Code = 'InvalidAuthorizationResponse'; Predicate = 'AuthorizationLocationCount' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackUriConstruction' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackScheme' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackHost' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackPort' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackUserInfo' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackFragment' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackPath' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackQueryParsing' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackKeyName' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackKeyMultiplicity' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackErrorAbsent' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackStateMatch' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackCodePresent' }
    @{ Phase = 'Callback'; Code = 'InvalidCallback'; Predicate = 'CallbackCodeLength' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'TokenTypeString' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'TokenTypeBearer' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'AccessTokenString' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'AccessTokenNonblank' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'AccessTokenNoNewline' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'IdTokenString' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'RefreshTokenFalsey' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'ScopeString' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Predicate = 'ScopeSyntax' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'TokenSplit' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'TokenPartCount' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderAlphabet' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderLength' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderBase64Decode' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderUtf8Decode' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderUtf8Construction' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonParse' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonRootObject' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonPropertySetConstruction' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonPropertiesRead' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonPropertyUnique' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonConversion' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonDispose' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsAlphabet' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsLength' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsBase64Decode' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsUtf8Decode' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsUtf8Construction' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonParse' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonRootObject' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonPropertySetConstruction' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonPropertiesRead' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonPropertyUnique' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonConversion' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonDispose' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderAlgorithmString' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderAlgorithmMatch' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderCriticalAbsent' }
    @{ Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'SignatureAlphabet' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'IssuerClaimString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'IssuerClaimMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'AudienceClaimString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'AudienceClaimMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'TenantClaimString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'TenantClaimMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'NonceClaimString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'NonceClaimMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'AuthorizedPartyString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'AuthorizedPartyMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'ObjectIdString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'ObjectIdFormat' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'ObjectIdNonzero' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'UsernameString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'UsernameMatch' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'SubjectString' }
    @{ Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Predicate = 'SubjectNonblank' }
    @{ Phase = 'TokenTimes'; Code = 'UnexpectedFailure'; Predicate = 'ClockRead' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'IssuedAtInteger' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'ExpiryInteger' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'ExpiryFuture' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'IssuedAtNotFuture' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'IssuedAtRecent' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'ExpiryAfterIssuedAt' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'NotBeforeInteger' }
    @{ Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Predicate = 'NotBeforeNotFuture' }
    @{ Phase = 'UserInfoSubject'; Code = 'InvalidUserInfoSubject'; Predicate = 'UserInfoSubjectString' }
    @{ Phase = 'UserInfoSubject'; Code = 'InvalidUserInfoSubject'; Predicate = 'UserInfoSubjectMatch' }
    @{ Phase = 'DiscoveryRequest'; Code = 'UnexpectedFailure'; Predicate = 'RequestInvocation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'StateCreation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'NonceCreation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'VerifierCreation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'ChallengeCreation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'AuthorizationFormCreation' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'AuthorizationUriConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'RequestInvocation' }
    @{ Phase = 'TokenRequest'; Code = 'UnexpectedFailure'; Predicate = 'TokenFormCreation' }
    @{ Phase = 'TokenRequest'; Code = 'UnexpectedFailure'; Predicate = 'RequestInvocation' }
    @{ Phase = 'UserInfoRequest'; Code = 'UnexpectedFailure'; Predicate = 'RequestInvocation' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseStatus' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseMediaType' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseLocations' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonParse' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonRootObject' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertySetConstruction' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertiesRead' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertyUnique' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion' }
    @{ Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonDispose' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseStatus' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseMediaType' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseLocations' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonParse' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonRootObject' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertySetConstruction' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertiesRead' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonPropertyUnique' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion' }
    @{ Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportUriConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportScheme' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportPort' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportUserInfo' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportFragment' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportHost' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportHandlerConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportRedirectPolicy' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportCookiePolicy' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportCredentialPolicy' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportProxyPolicy' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportTimeoutConfiguration' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportMethodConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportHeaderConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportBodyConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportSend' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportAdvertisedLimit' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamOpen' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportReadBufferConstruction' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportRead' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamedLimit' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferWrite' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportLocationRead' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseProjection' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportUtf8Decode' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestDispose' }
    @{ Phase = 'DiscoveryRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportUriConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportScheme' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportPort' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportUserInfo' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportFragment' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportHost' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportHandlerConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportRedirectPolicy' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportCookiePolicy' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportCredentialPolicy' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportProxyPolicy' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportTimeoutConfiguration' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportMethodConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportHeaderConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportBodyConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportSend' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportAdvertisedLimit' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamOpen' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportReadBufferConstruction' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportRead' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamedLimit' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferWrite' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportLocationRead' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseProjection' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportUtf8Decode' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestDispose' }
    @{ Phase = 'AuthorizationRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportUriConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportScheme' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportPort' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportUserInfo' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportFragment' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportHost' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportHandlerConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportRedirectPolicy' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportCookiePolicy' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportCredentialPolicy' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportProxyPolicy' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportTimeoutConfiguration' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportMethodConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportHeaderConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportBodyConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportSend' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportAdvertisedLimit' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamOpen' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportReadBufferConstruction' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportRead' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamedLimit' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferWrite' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportLocationRead' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseProjection' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportUtf8Decode' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestDispose' }
    @{ Phase = 'TokenRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportUriConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportScheme' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportPort' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportUserInfo' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportFragment' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportHost' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportHandlerConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportRedirectPolicy' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportCookiePolicy' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportCredentialPolicy' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportProxyPolicy' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportTimeoutConfiguration' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportMethodConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportHeaderConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportBodyConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportSend' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportAdvertisedLimit' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamOpen' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportReadBufferConstruction' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportRead' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamedLimit' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferWrite' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportLocationRead' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseProjection' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportUtf8Decode' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportStreamDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportResponseDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportDeadlineDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportBufferDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportRequestDispose' }
    @{ Phase = 'UserInfoRequest'; Code = 'TransportFailure'; Predicate = 'TransportClientDispose' }
    @{ Phase = 'Configuration'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'Cookie'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'DiscoveryRequest'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'DiscoveryResponse'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'DiscoveryMetadata'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'AuthorizationRequest'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'AuthorizationResponse'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'Callback'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'TokenRequest'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'TokenResponse'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'TokenEncoding'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'TokenBinding'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'TokenTimes'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'UserInfoRequest'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'UserInfoResponse'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'UserInfoSubject'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
    @{ Phase = 'Unknown'; Code = 'UnexpectedFailure'; Predicate = 'UnexpectedFailure' }
)

BeforeAll {
    $script:probeSource = Get-Content (Join-Path $PSScriptRoot '../.github/validation/LabSessionProbe.ps1') -Raw
    $parseTokens = $null; $parseErrors = $null
    $script:probeAst = [Management.Automation.Language.Parser]::ParseInput($script:probeSource, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Session probe source must parse before offline fixtures load.' }
    $definitions = @($script:probeAst.EndBlock.Statements)
    if ($script:probeAst.BeginBlock -or $script:probeAst.ProcessBlock -or $script:probeAst.ParamBlock -or
        @($definitions | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -ne 0) {
        throw 'Offline fixture permits only top-level function declarations.'
    }
    $transport = @($definitions | Where-Object Name -CEQ 'Send-LabProbeRequest')
    if ($transport.Count -ne 1) { throw 'Expected exactly one isolated native transport.' }
    $factory = @($definitions | Where-Object Name -CEQ 'New-LabProbeHttpHandler')
    if ($factory.Count -ne 1) { throw 'Expected exactly one excluded native handler factory.' }
    $script:probeTransportSource = $transport[0].Extent.Text + $factory[0].Extent.Text
    foreach ($definition in $definitions) {
        if ($definition.Name -cin @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) { continue }
        # Block direct native networking outside the excluded transport. Cmdlet
        # transports also have throwing Pester guards below.
        if ($definition.Extent.Text -match '(?i)HttpClient|HttpWebRequest|WebClient|TcpClient|Socket|SendAsync|DownloadString|Start-Process|Invoke-Expression') {
            throw 'Network-capable code outside the excluded transport is not allowed in the offline harness.'
        }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Send-LabProbeRequest {
        param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body, [hashtable]$Diagnostic)
        throw 'Native HTTP is unavailable in this offline test suite.'
    }
    # Exact pre-scope-policy source is checked before parsing and is NEVER dot-sourced.
    # The isolated AST loader excludes BOTH native factory and native transport.
    $baselinePath = Join-Path $PSScriptRoot 'fixtures/LabSessionProbe.ScopeBaseline.ps1'
    if ((Get-FileHash $baselinePath -Algorithm SHA256).Hash -cne '71591B0BB059220A64043B3232E445E7D0247CF1CB3BF19F0127791B3060A123') {
        throw 'The immutable pre-scope-policy baseline hash changed.'
    }
    $baselineSource = Get-Content $baselinePath -Raw
    $baselineTokens = $null; $baselineErrors = $null
    $baselineAst = [Management.Automation.Language.Parser]::ParseInput($baselineSource, [ref]$baselineTokens, [ref]$baselineErrors)
    if ($baselineErrors.Count -ne 0) { throw 'Immutable baseline source must parse.' }
    $baselineDefinitions = @($baselineAst.EndBlock.Statements)
    if ($baselineAst.BeginBlock -or $baselineAst.ProcessBlock -or $baselineAst.ParamBlock -or
        @($baselineDefinitions | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -ne 0) {
        throw 'Baseline fixture permits only top-level function declarations.'
    }
    foreach ($excluded in @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) {
        if (@($baselineDefinitions | Where-Object Name -CEQ $excluded).Count -ne 1) { throw 'Baseline isolation boundary missing.' }
    }
    foreach ($definition in $baselineDefinitions) {
        if ($definition.Name -cin @('Send-LabProbeRequest', 'New-LabProbeHttpHandler')) { continue }
        $renamed = $definition.Extent.Text
        if ($renamed -match '(?i)HttpClient|HttpWebRequest|WebClient|TcpClient|Socket|SendAsync|DownloadString|Start-Process|Invoke-Expression') {
            throw 'Network-capable baseline code outside the excluded transport is forbidden.'
        }
        foreach ($original in @($baselineDefinitions.Name | Sort-Object Length -Descending)) {
            $replacement = $original.Replace('-Lab', '-BaselineLab')
            $renamed = [regex]::Replace($renamed, ('\b' + [regex]::Escape($original) + '\b'), $replacement)
        }
        . ([scriptblock]::Create($renamed))
    }
    function Send-BaselineLabProbeRequest {
        param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$Body, [hashtable]$Diagnostic)
        throw 'Native HTTP is unavailable in the immutable baseline test suite.'
    }
    function ConvertTo-ProbeTestSegment {
        param([string]$Text)
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    function New-ProbeTestJsonResponse {
        param([string]$Stage, $Value)
        $response = @{ Status = 200; Locations = @(); ContentType = 'application/json'; Body = ($Value | ConvertTo-Json -Depth 16 -Compress) }
        if ($script:probeResponseOverrides.Contains($Stage)) {
            foreach ($key in $script:probeResponseOverrides[$Stage].Keys) { $response[$key] = $script:probeResponseOverrides[$Stage][$key] }
        }
        return $response
    }
    function Set-ProbeTestProperties {
        param($Value, $Overrides, [string[]]$Remove = @())
        foreach ($key in $Overrides.Keys) { $Value[$key] = $Overrides[$key] }
        foreach ($key in $Remove) { [void]$Value.Remove($key) }
    }
    function ConvertTo-ProbeNormalizedRequestTrace {
        # Compare destinations, methods, headers, and decoded query/form field
        # values. Sorting and decoding normalize field order and percent-encoding,
        # in addition to fresh transaction values; this is NOT a raw-byte trace.
        # Exact baseline source checks below separately pin form serialization
        # and the original authorization-query and token-body expressions.
        param($Requests)
        $normalized = foreach ($request in $Requests) {
            $uriParts = $request.Uri.Split('?', 2)
            $query = [ordered]@{}
            if ($uriParts.Count -eq 2) {
                $parsed = [Web.HttpUtility]::ParseQueryString($uriParts[1])
                foreach ($key in @($parsed.AllKeys | Sort-Object -CaseSensitive)) {
                    $values = @($parsed.GetValues($key))
                    if ($key -cin @('state', 'nonce', 'code_challenge')) {
                        $values.Count | Should -Be 1
                        $values[0] | Should -Match '^[A-Za-z0-9_-]{43}$'
                        $values = @('<transaction-' + $key + '>')
                    }
                    $query[$key] = $values
                }
            }
            $headers = [ordered]@{}
            foreach ($key in @($request.Headers.Keys | Sort-Object -CaseSensitive)) { $headers[$key] = $request.Headers[$key] }
            $body = $request.Body
            if ($request.Method -ceq 'POST' -and $null -ne $body) {
                $parsed = [Web.HttpUtility]::ParseQueryString($body)
                $body = [ordered]@{}
                foreach ($key in @($parsed.AllKeys | Sort-Object -CaseSensitive)) {
                    $values = @($parsed.GetValues($key))
                    if ($key -ceq 'code_verifier') {
                        $values.Count | Should -Be 1
                        $values[0] | Should -Match '^[A-Za-z0-9_-]{43}$'
                        $values = @('<transaction-code_verifier>')
                    }
                    $body[$key] = $values
                }
            }
            [ordered]@{ Uri = $uriParts[0]; QueryPresent = ($uriParts.Count -eq 2); Query = $query; Method = $request.Method; Headers = $headers; Body = $body }
        }
        return ConvertTo-Json -InputObject @($normalized) -Depth 16 -Compress
    }
    function Invoke-ProbeTest {
        if (-not $script:probeCompareBaseline) { return Invoke-LabSessionProbe @script:probeArguments }
        $requestStart = $script:probeRequests.Count
        $candidateOutput = [Collections.Generic.List[object]]::new(); $candidateError = $null
        try { Invoke-LabSessionProbe @script:probeArguments *>&1 | ForEach-Object { $candidateOutput.Add($_) } } catch { $candidateError = $_ }
        $candidateRequests = @($script:probeRequests | Select-Object -Skip $requestStart)
        $savedRequests = $script:probeRequests; $savedQuery = $script:probeAuthorizeQuery; $savedCount = $script:probeAuthorizeCount
        $baselineOutput = [Collections.Generic.List[object]]::new(); $baselineError = $null
        try {
            $script:probeRequests = [Collections.Generic.List[object]]::new()
            $script:probeAuthorizeQuery = $null; $script:probeAuthorizeCount = 0
            try { Invoke-BaselineLabSessionProbe @script:probeArguments *>&1 | ForEach-Object { $baselineOutput.Add($_) } } catch { $baselineError = $_ }
            $baselineRequests = $script:probeRequests.ToArray()
        } finally {
            $script:probeRequests = $savedRequests; $script:probeAuthorizeQuery = $savedQuery; $script:probeAuthorizeCount = $savedCount
        }
        # All decisions, receipts and error labels stay equal here, except for
        # the explicit returned-scope predicate rename. Intentional acceptance
        # expansion has its own helper below and never weakens this comparison.
        # Requests use the documented semantic normalization, not bytewise.
        ($null -eq $candidateError) | Should -Be ($null -eq $baselineError)
        (ConvertTo-ProbeNormalizedRequestTrace $candidateRequests) | Should -BeExactly (ConvertTo-ProbeNormalizedRequestTrace $baselineRequests)
        if ($null -eq $candidateError) {
            (ConvertTo-Json -InputObject $candidateOutput.ToArray() -Depth 16 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $baselineOutput.ToArray() -Depth 16 -Compress)
        } else {
            $baselineOutput.Count | Should -Be 0
            $expectedError = $baselineError.Exception.Message
            if ($expectedError -ceq "$script:probeSafeError Phase=TokenResponse; Code=InvalidTokenResponse; Predicate=ScopeAllowedGrammar.") {
                $expectedError = "$script:probeSafeError Phase=TokenResponse; Code=InvalidTokenResponse; Predicate=ScopeSyntax."
            }
            $candidateError.Exception.Message | Should -BeExactly $expectedError
        }
        foreach ($item in $candidateOutput) { Write-Output $item }
        if ($null -ne $candidateError) { throw $candidateError }
    }
    function ConvertTo-ProbeExactRequestTrace {
        # Only dictionary enumeration is stabilized. Raw URI, query and body strings,
        # methods and every header value are compared without normalization.
        param($Requests)
        $trace = foreach ($request in $Requests) {
            $headers = [ordered]@{}
            foreach ($key in @($request.Headers.Keys | Sort-Object -CaseSensitive)) { $headers[$key] = $request.Headers[$key] }
            [ordered]@{ Uri = $request.Uri; Method = $request.Method; Headers = $headers; Body = $request.Body }
        }
        return ConvertTo-Json -InputObject @($trace) -Depth 16 -Compress
    }
    function Assert-ProbeReturnedScopeExpansion {
        param([Parameter(Mandatory)][string]$Scope)
        # Intentional policy difference only: old source rejects this returned
        # name, new source accepts its syntax. No request scope is expanded.
        $script:probeTokenOverrides.scope = $Scope
        $script:probeScopeCandidateRandomCalls = 0
        $script:probeScopeBaselineRandomCalls = 0
        Mock ConvertTo-LabProbeBase64Url {
            param([byte[]]$Bytes)
            $script:probeScopeCandidateRandomCalls++
            switch ($script:probeScopeCandidateRandomCalls) {
                1 { return ('s' * 43) }
                2 { return ('n' * 43) }
                3 { return ('v' * 43) }
                4 { return (& $script:probeBase64Function $Bytes) }
                default { throw 'Unexpected synthetic transaction encoding call.' }
            }
        }
        Mock ConvertTo-BaselineLabProbeBase64Url {
            param([byte[]]$Bytes)
            $script:probeScopeBaselineRandomCalls++
            switch ($script:probeScopeBaselineRandomCalls) {
                1 { return ('s' * 43) }
                2 { return ('n' * 43) }
                3 { return ('v' * 43) }
                4 { return (& $script:probeBase64Function $Bytes) }
                default { throw 'Unexpected synthetic transaction encoding call.' }
            }
        }
        $requestStart = $script:probeRequests.Count
        $candidateOutput = [Collections.Generic.List[object]]::new(); $candidateError = $null
        try { Invoke-LabSessionProbe @script:probeArguments *>&1 | ForEach-Object { $candidateOutput.Add($_) } } catch { $candidateError = $_ }
        $candidateRequests = @($script:probeRequests | Select-Object -Skip $requestStart)
        $savedRequests = $script:probeRequests; $savedQuery = $script:probeAuthorizeQuery; $savedCount = $script:probeAuthorizeCount
        $baselineOutput = [Collections.Generic.List[object]]::new(); $baselineError = $null
        try {
            $script:probeRequests = [Collections.Generic.List[object]]::new()
            $script:probeAuthorizeQuery = $null; $script:probeAuthorizeCount = 0
            try { Invoke-BaselineLabSessionProbe @script:probeArguments *>&1 | ForEach-Object { $baselineOutput.Add($_) } } catch { $baselineError = $_ }
            $baselineRequests = $script:probeRequests.ToArray()
        } finally {
            $script:probeRequests = $savedRequests; $script:probeAuthorizeQuery = $savedQuery; $script:probeAuthorizeCount = $savedCount
        }
        $candidateError | Should -BeNullOrEmpty
        $candidateOutput.Count | Should -Be 1
        (ConvertTo-Json -InputObject $candidateOutput[0] -Compress) | Should -BeExactly '{"ServerBackedSessionReuse":true,"ExpectedTenantAndCurrentName":true,"UserInfoSubjectMatched":true,"TamperProofAgainstCandidate":false}'
        $baselineError | Should -Not -BeNullOrEmpty
        $baselineError.Exception.Message | Should -BeExactly "$script:probeSafeError Phase=TokenResponse; Code=InvalidTokenResponse; Predicate=ScopeAllowedGrammar."
        $baselineOutput.Count | Should -Be 0
        $candidateRequests.Count | Should -Be 4
        $baselineRequests.Count | Should -Be 3
        $script:probeScopeCandidateRandomCalls | Should -Be 4
        $script:probeScopeBaselineRandomCalls | Should -Be 4
        (ConvertTo-ProbeExactRequestTrace $candidateRequests[0..2]) | Should -BeExactly (ConvertTo-ProbeExactRequestTrace $baselineRequests)
        ([Web.HttpUtility]::ParseQueryString(([uri]$candidateRequests[1].Uri).Query))['scope'] | Should -BeExactly 'openid profile'
        ([Web.HttpUtility]::ParseQueryString($candidateRequests[2].Body))['scope'] | Should -BeExactly 'openid profile'
        $candidateRequests[3].Uri | Should -BeExactly $script:probeUserInfoEndpoint
        $candidateRequests[3].Method | Should -BeExactly 'GET'
        $candidateRequests[3].Headers.Count | Should -Be 1
        $candidateRequests[3].Headers.Authorization | Should -BeExactly 'Bearer synthetic-opaque-access-token'
        $candidateRequests[3].Body | Should -BeNullOrEmpty
        Should -Invoke Send-LabProbeRequest -Times 4 -Exactly
        Should -Invoke Send-BaselineLabProbeRequest -Times 3 -Exactly
    }
    $probeDefinition = @($definitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0]
    $probeTry = @($probeDefinition.Body.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[0]
    $emissionSource = $probeTry.CatchClauses[0].Body.Extent.Text
    # Exercise the exact public catch body independently to test labels that
    # ordinary protocol input cannot assign. No transport is loaded here.
    $script:probeFailureEmission = [scriptblock]::Create($emissionSource.Substring(1, $emissionSource.Length - 2))
    $script:probeBase64Function = (Get-Command ConvertTo-LabProbeBase64Url -CommandType Function).ScriptBlock
    $script:probeDefinitions = $definitions
    $script:probeBaselineDefinitions = $baselineDefinitions
    $script:probeFormFunction = (Get-Command ConvertTo-LabProbeForm -CommandType Function).ScriptBlock
    $script:probeReadResponseFunction = (Get-Command Read-LabProbeResponse -CommandType Function).ScriptBlock
    $script:probeBaselineReadResponseFunction = (Get-Command Read-BaselineLabProbeResponse -CommandType Function).ScriptBlock
    $script:probeSafeError = 'Server-backed session probe failed; no live acceptance. Sensitive details suppressed.'
    function Assert-ProbeTestFailure {
        param([string]$Phase, [string]$Code, [int]$Requests, [Parameter(Mandatory)][string]$Predicate, [scriptblock]$Action = { Invoke-ProbeTest })
        $before = $script:probeRequests.Count
        $messages = [Collections.Generic.List[object]]::new()
        $caught = $null
        $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; $InformationPreference = 'Continue'; $WarningPreference = 'Continue'
        try { & $Action *>&1 | ForEach-Object { $messages.Add($_) } } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $expected = "$script:probeSafeError Phase=$Phase; Code=$Code; Predicate=$Predicate."
        $caught.Exception.Message | Should -BeExactly $expected
        $caught.Exception.InnerException | Should -BeNullOrEmpty
        $messages.Count | Should -Be 0
        ($script:probeRequests.Count - $before) | Should -Be $Requests
        # Inspect the entire public error and ordinary/verbose/debug/information
        # streams, not only Message. Test markers never contain real credentials.
        $rendered = @($caught.ToString(), $caught.Exception.ToString(), ($caught | Out-String),
            ($caught | Format-List * -Force | Out-String), ($caught.Exception | Format-List * -Force | Out-String),
            ($caught.Exception.Data | Out-String), [string]$caught.TargetObject, [string]$caught.ErrorDetails,
            [string]$caught.FullyQualifiedErrorId, [string]$caught.CategoryInfo, [string]$caught.ScriptStackTrace,
            [string]$caught.InvocationInfo.PositionMessage) -join "`n"
        $rendered | Should -Not -Match 'fixture-sensitive|synthetic-cookie|synthetic-authorization|synthetic-opaque|fixture@example|diagnostic-secret|11111111-1111|22222222-2222|33333333-3333'
    }
}

Describe 'Server-backed session readback with synthetic, offline evidence' {
    BeforeEach {
        $script:probeArguments = @{
            TenantId = '11111111-1111-4111-8111-111111111111'
            ClientId = '22222222-2222-4222-8222-222222222222'
            ExpectedUpn = 'fixture@example.invalid'
            CookieName = 'ESTSAUTH'
            Cookie = 'synthetic-cookie-never-a-real-credential'
        }
        $script:probeAuthority = 'https://login.microsoftonline.com/' + $script:probeArguments.TenantId
        $script:probeRedirect = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        $script:probeDiscovery = $script:probeAuthority + '/v2.0/.well-known/openid-configuration'
        $script:probeAuthorizeEndpoint = $script:probeAuthority + '/oauth2/v2.0/authorize'
        $script:probeTokenEndpoint = $script:probeAuthority + '/oauth2/v2.0/token'
        $script:probeUserInfoEndpoint = 'https://graph.microsoft.com/oidc/userinfo'
        $script:probeRequests = [Collections.Generic.List[object]]::new()
        $script:probeAuthorizeQuery = $null
        $script:probeAuthorizeCount = 0
        $script:probeCallbackMode = 'success'
        $script:probeRedirectOverride = $null
        $script:probeThrowStage = ''
        $script:probeException = $null
        $script:probeMetadataOverrides = @{}
        $script:probeMetadataRemove = @()
        $script:probeHeaderOverrides = @{}
        $script:probeClaimsOverrides = @{}
        $script:probeClaimsRemove = @()
        $script:probeTokenOverrides = @{}
        $script:probeTokenRemove = @()
        $script:probeUserInfoOverrides = @{}
        $script:probeUserInfoRemove = @()
        $script:probeResponseOverrides = @{}
        $script:probeRawHeader = $null
        $script:probeRawClaims = $null
        $script:probeIdTokenMode = ''
        $script:probeSignature = 'c3ludGhldGljLXNpZ25hdHVyZQ'
        $script:probeCompareBaseline = $true
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in offline session tests.' }
        Mock Invoke-WebRequest { throw 'Real HTTP is forbidden in offline session tests.' }
        $script:probeSyntheticRequest = {
            param($Uri, $Method = 'GET', $Headers = @{}, $Body, [hashtable]$Diagnostic)
            if ($null -eq $Headers) { $Headers = @{} }
            $script:probeRequests.Add(@{ Uri = [string]$Uri; Method = $Method; Headers = @{} + $Headers; Body = $Body })
            if ($Uri -ceq $script:probeDiscovery) {
                if ($script:probeThrowStage -eq 'Discovery') {
                    if ($null -ne $script:probeException) { throw $script:probeException }
                    throw 'fixture-sensitive-discovery-detail'
                }
                $metadata = @{
                    issuer = $script:probeAuthority + '/v2.0'
                    authorization_endpoint = $script:probeAuthorizeEndpoint
                    token_endpoint = $script:probeTokenEndpoint
                    userinfo_endpoint = $script:probeUserInfoEndpoint
                }
                Set-ProbeTestProperties $metadata $script:probeMetadataOverrides $script:probeMetadataRemove
                return New-ProbeTestJsonResponse Discovery $metadata
            }
            if ($Uri.StartsWith($script:probeAuthorizeEndpoint + '?', [StringComparison]::Ordinal)) {
                if ($script:probeThrowStage -eq 'Authorization') {
                    if ($null -ne $script:probeException) { throw $script:probeException }
                    throw 'fixture-sensitive-cookie-detail'
                }
                $script:probeAuthorizeCount++
                if ($null -eq $script:probeAuthorizeQuery) { $script:probeAuthorizeQuery = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query) }
                $state = [uri]::EscapeDataString($script:probeAuthorizeQuery['state'])
                $query = "code=synthetic-authorization-code&state=$state"
                switch ($script:probeCallbackMode) {
                    'missing-state' { $query = 'code=synthetic-authorization-code' }
                    'wrong-state' { $query = 'code=synthetic-authorization-code&state=wrong-state' }
                    'empty-state' { $query = 'code=synthetic-authorization-code&state=' }
                    'duplicate-state' { $query += "&state=$state" }
                    'encoded-duplicate-state' { $query += "&st%61te=$state" }
                    'case-duplicate-state' { $query += "&STATE=$state" }
                    'missing-code' { $query = "state=$state" }
                    'empty-code' { $query = "state=$state&code=" }
                    'blank-code' { $query = "state=$state&code=%20%20" }
                    'duplicate-code' { $query += '&code=second-code' }
                    'encoded-duplicate-code' { $query += '&co%64e=second-code' }
                    'case-duplicate-code' { $query += '&CODE=second-code' }
                    'oversize-code' { $query = "state=$state&code=" + ('x' * 16385) }
                    'boundary-code' { $query = "state=$state&code=" + ('x' * 16384) }
                    'unnamed-field' { $query += '&unkeyed-value' }
                    'duplicate-extra-field' { $query += '&extra=one&extra=two' }
                    'login-required' { $query += '&error=login_required&error_description=fixture-sensitive-login-detail' }
                    'interaction-required' { $query += '&error=interaction_required' }
                    'consent-required' { $query += '&error=consent_required' }
                    'access-denied' { $query += '&error=access_denied' }
                }
                $location = $script:probeRedirect + '?' + $query
                if ($script:probeCallbackMode -eq 'loop') { $location = $Uri }
                if ($null -ne $script:probeRedirectOverride) { $location = $script:probeRedirectOverride }
                $response = @{ Status = 302; Locations = @($location); ContentType = 'text/html'; Body = '' }
                if ($script:probeResponseOverrides.Contains('Authorization')) {
                    foreach ($key in $script:probeResponseOverrides.Authorization.Keys) { $response[$key] = $script:probeResponseOverrides.Authorization[$key] }
                }
                return $response
            }
            if ($Uri -ceq $script:probeTokenEndpoint) {
                if ($script:probeThrowStage -eq 'Token') {
                    if ($null -ne $script:probeException) { throw $script:probeException }
                    throw 'fixture-sensitive-code-and-token-detail'
                }
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $header = @{ alg = 'RS256'; typ = 'JWT'; kid = 'synthetic-only' }
                $claims = @{
                    iss = $script:probeAuthority + '/v2.0'; tid = $script:probeArguments.TenantId
                    aud = $script:probeArguments.ClientId; nonce = $script:probeAuthorizeQuery['nonce']
                    oid = '33333333-3333-4333-8333-333333333333'; sub = 'synthetic-pairwise-subject'
                    preferred_username = 'fixture@example.invalid'; iat = $now; exp = $now + 600
                }
                Set-ProbeTestProperties $header $script:probeHeaderOverrides
                Set-ProbeTestProperties $claims $script:probeClaimsOverrides $script:probeClaimsRemove
                $headerJson = $header | ConvertTo-Json -Depth 16 -Compress
                $claimsJson = $claims | ConvertTo-Json -Depth 16 -Compress
                if ($null -ne $script:probeRawHeader) { $headerJson = $script:probeRawHeader }
                if ($null -ne $script:probeRawClaims) { $claimsJson = $script:probeRawClaims }
                $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.' + $script:probeSignature
                switch ($script:probeIdTokenMode) {
                    'opaque' { $idToken = 'opaque-not-an-id-token' }
                    'empty' { $idToken = '' }
                    'two-parts' { $idToken = 'e30.e30' }
                    'four-parts' { $idToken += '.fourth' }
                    'empty-header' { $idToken = '.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'empty-payload' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '..c2ln' }
                    'invalid-header-alphabet' { $idToken = '!!!.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-alphabet' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.!!!.c2ln' }
                    'invalid-header-length' { $idToken = 'a.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-length' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '.a.c2ln' }
                    'invalid-header-utf8' { $idToken = '_w.' + (ConvertTo-ProbeTestSegment $claimsJson) + '.c2ln' }
                    'invalid-payload-utf8' { $idToken = (ConvertTo-ProbeTestSegment $headerJson) + '._w.c2ln' }
                    'empty-signature' { $idToken = $idToken.Substring(0, $idToken.LastIndexOf('.') + 1) }
                    'invalid-signature-alphabet' { $idToken = $idToken.Substring(0, $idToken.LastIndexOf('.') + 1) + '!!!' }
                }
                $tokens = @{ token_type = 'Bearer'; access_token = 'synthetic-opaque-access-token'; id_token = $idToken }
                Set-ProbeTestProperties $tokens $script:probeTokenOverrides $script:probeTokenRemove
                return New-ProbeTestJsonResponse Token $tokens
            }
            if ($Uri -ceq $script:probeUserInfoEndpoint) {
                if ($script:probeThrowStage -eq 'UserInfo') {
                    if ($null -ne $script:probeException) { throw $script:probeException }
                    throw 'fixture-sensitive-userinfo-detail'
                }
                $user = @{ sub = 'synthetic-pairwise-subject'; name = 'Synthetic fixture only' }
                Set-ProbeTestProperties $user $script:probeUserInfoOverrides $script:probeUserInfoRemove
                return New-ProbeTestJsonResponse UserInfo $user
            }
            throw 'Offline fixture refused an unexpected destination; no HTTP was attempted.'
        }
        Mock Send-LabProbeRequest { param($Uri, $Method = 'GET', $Headers = @{}, $Body, [hashtable]$Diagnostic); & $script:probeSyntheticRequest @PSBoundParameters }
        Mock Send-BaselineLabProbeRequest { param($Uri, $Method = 'GET', $Headers = @{}, $Body, [hashtable]$Diagnostic); & $script:probeSyntheticRequest @PSBoundParameters }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'returns only the bounded receipt after a synthetic current-transaction ID token and matching UserInfo' {
        $result = Invoke-ProbeTest
        $result.ServerBackedSessionReuse | Should -BeTrue
        $result.ExpectedTenantAndCurrentName | Should -BeTrue
        $result.UserInfoSubjectMatched | Should -BeTrue
        $result.TamperProofAgainstCandidate | Should -BeFalse
        (@($result.Keys) | Sort-Object) -join ',' | Should -BeExactly 'ExpectedTenantAndCurrentName,ServerBackedSessionReuse,TamperProofAgainstCandidate,UserInfoSubjectMatched'
        ($result | ConvertTo-Json -Compress) | Should -Not -Match 'synthetic|fixture@example|11111111|22222222|33333333'
        ($result | ConvertTo-Json -Compress) | Should -BeExactly '{"ServerBackedSessionReuse":true,"ExpectedTenantAndCurrentName":true,"UserInfoSubjectMatched":true,"TamperProofAgainstCandidate":false}'
        Should -Invoke Send-LabProbeRequest -Times 4 -Exactly
    }
    It 'binds state, nonce and S256 PKCE and requests only silent openid profile authorization' {
        $null = Invoke-ProbeTest
        $query = $script:probeAuthorizeQuery
        $query['scope'] | Should -BeExactly 'openid profile'
        $query['prompt'] | Should -BeExactly 'none'
        $query['response_type'] | Should -BeExactly 'code'
        $query['response_mode'] | Should -BeExactly 'query'
        $query['client_id'] | Should -BeExactly $script:probeArguments.ClientId
        $query['redirect_uri'] | Should -BeExactly $script:probeRedirect
        $query['code_challenge_method'] | Should -BeExactly 'S256'
        $query['state'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $query['nonce'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $query['state'] | Should -Not -BeExactly $query['nonce']
        (@($query.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code_challenge,code_challenge_method,nonce,prompt,redirect_uri,response_mode,response_type,scope,state'
        $request = $script:probeRequests[2]
        $request.Method | Should -BeExactly 'POST'
        $request.Uri | Should -BeExactly $script:probeTokenEndpoint
        $form = [Web.HttpUtility]::ParseQueryString($request.Body)
        $form['grant_type'] | Should -BeExactly 'authorization_code'
        $form['client_id'] | Should -BeExactly $script:probeArguments.ClientId
        $form['redirect_uri'] | Should -BeExactly $script:probeRedirect
        $form['scope'] | Should -BeExactly 'openid profile'
        $form['code'] | Should -BeExactly 'synthetic-authorization-code'
        $form['code_verifier'] | Should -Match '^[A-Za-z0-9_-]{43}$'
        $expectedChallenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($form['code_verifier']))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $query['code_challenge'] | Should -BeExactly $expectedChallenge
        (@($form.AllKeys) | Sort-Object) -join ',' | Should -BeExactly 'client_id,code,code_verifier,grant_type,redirect_uri,scope'
        $request.Body | Should -Not -Match 'refresh_token|offline_access|client_secret'
    }
    It 'sends the cookie only to authorization and the opaque bearer only to UserInfo' {
        $null = Invoke-ProbeTest
        $script:probeRequests[0].Headers.Count | Should -Be 0
        $script:probeRequests[1].Headers.Count | Should -Be 1
        $script:probeRequests[1].Headers.Cookie | Should -BeExactly ('ESTSAUTH=' + $script:probeArguments.Cookie)
        $script:probeRequests[2].Headers.Count | Should -Be 0
        $script:probeRequests[3].Uri | Should -BeExactly $script:probeUserInfoEndpoint
        $script:probeRequests[3].Headers.Count | Should -Be 1
        $script:probeRequests[3].Headers.Authorization | Should -BeExactly 'Bearer synthetic-opaque-access-token'
        foreach ($request in $script:probeRequests) {
            $request.Uri | Should -Not -Match 'synthetic-cookie|synthetic-opaque-access-token|fixture@example'
        }
    }
    It 'uses distinct state, nonce and verifier for a new transaction' {
        $null = Invoke-ProbeTest
        $firstQuery = $script:probeAuthorizeQuery
        $firstVerifier = ([Web.HttpUtility]::ParseQueryString($script:probeRequests[2].Body))['code_verifier']
        $script:probeAuthorizeQuery = $null
        $null = Invoke-ProbeTest
        $script:probeAuthorizeQuery['state'] | Should -Not -BeExactly $firstQuery['state']
        $script:probeAuthorizeQuery['nonce'] | Should -Not -BeExactly $firstQuery['nonce']
        ([Web.HttpUtility]::ParseQueryString($script:probeRequests[6].Body))['code_verifier'] | Should -Not -BeExactly $firstVerifier
    }
    It 'accepts the other explicitly permitted cookie name without changing its boundary' {
        $script:probeArguments.CookieName = 'ESTSAUTHPERSISTENT'
        $null = Invoke-ProbeTest
        $script:probeRequests[1].Headers.Cookie | Should -BeExactly ('ESTSAUTHPERSISTENT=' + $script:probeArguments.Cookie)
    }
    It 'accepts a current UPN case variation, matching authorized party, and present valid nbf' {
        $script:probeClaimsOverrides = @{ preferred_username = 'FIXTURE@EXAMPLE.INVALID'; azp = $script:probeArguments.ClientId; nbf = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1 }
        (Invoke-ProbeTest).UserInfoSubjectMatched | Should -BeTrue
    }
    It 'accepts a 303 callback without following the nativeclient URL' {
        $script:probeResponseOverrides.Authorization = @{ Status = 303 }
        $null = Invoke-ProbeTest
        @($script:probeRequests | Where-Object { $_.Uri.StartsWith($script:probeRedirect) }).Count | Should -Be 0
    }

    It 'requires explicit <Field> before any request' -ForEach @('TenantId', 'ClientId', 'ExpectedUpn') {
        [void]$script:probeArguments.Remove($_)
        Assert-ProbeTestFailure Configuration InvalidConfiguration 0 (@{ TenantId = 'TenantFormat'; ClientId = 'ClientFormat'; ExpectedUpn = 'UpnFormat' }[$_])
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects malformed tenant/client IDs before HTTP: <Value>' -ForEach @('', 'organizations', 'common', '00000000-0000-0000-0000-000000000000', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', "11111111-1111-4111-8111-111111111111`n", '11111111-1111-4111-8111-111111111111/extra') {
        foreach ($field in @('TenantId', 'ClientId')) {
            $original = $script:probeArguments[$field]
            $script:probeArguments[$field] = $_
            Assert-ProbeTestFailure Configuration InvalidConfiguration 0 (($field -replace 'Id$','') + $(if ($_ -eq '00000000-0000-0000-0000-000000000000') { 'Nonzero' } else { 'Format' }))
            $script:probeArguments[$field] = $original
        }
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'permits an explicitly selected common-client compatibility scenario without assuming live support' -ForEach @('04b07795-8ddb-461a-bbee-02f9e1bf7b46', '14d82eec-204b-4c2f-b7e8-296a70dab67e') {
        { Assert-LabProbeConfiguration $script:probeArguments.TenantId $_ $script:probeArguments.ExpectedUpn } | Should -Not -Throw
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects missing or malformed expected UPNs' -ForEach @('', 'fixture', 'fixture@@example.invalid', ' fixture@example.invalid', "fixture@example.invalid`n", (('x' * 310) + '@example.invalid')) {
        $script:probeArguments.ExpectedUpn = $_
        Assert-ProbeTestFailure Configuration InvalidConfiguration 0 $(if ($_.Length -gt 320) { 'UpnLength' } else { 'UpnFormat' })
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects invalid cookie material without any request' -ForEach @('', "cookie`nvalue", "cookie`rvalue", 'cookie;second=value', 'cookie,value', 'cookie value', 'cookie"value', 'cookie\value', ('x' * 32769)) {
        $script:probeArguments.Cookie = $_
        Assert-ProbeTestFailure Cookie InvalidCookie 0 $(if ($_.Length -gt 32768) { 'CookieLength' } else { 'CookieAlphabet' })
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }
    It 'rejects absent or unknown cookie names' -ForEach @('', 'estsauth', 'OTHER', "ESTSAUTH`r`nInjected: x") {
        $script:probeArguments.CookieName = $_
        Assert-ProbeTestFailure Cookie InvalidCookie 0 CookieName
        Should -Invoke Send-LabProbeRequest -Times 0 -Exactly
    }

    It 'requires every pinned discovery endpoint: <_>' -ForEach @('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint') {
        $script:probeMetadataRemove = @($_)
        Assert-ProbeTestFailure DiscoveryMetadata InvalidMetadata 1 (@{ issuer = 'IssuerMetadataString'; authorization_endpoint = 'AuthorizationMetadataString'; token_endpoint = 'TokenMetadataString'; userinfo_endpoint = 'UserInfoMetadataString' }[$_])
        Should -Invoke Send-LabProbeRequest -Times 1 -Exactly
    }
    It 'rejects alternate or non-string discovery metadata: <Field>' -ForEach @(
        @{ Field = 'issuer'; Value = 'https://login.microsoftonline.com/common/v2.0' },
        @{ Field = 'issuer'; Value = @('https://login.microsoftonline.com/common/v2.0') },
        @{ Field = 'authorization_endpoint'; Value = 'https://example.invalid/authorize' },
        @{ Field = 'token_endpoint'; Value = 'https://login.microsoftonline.com/common/oauth2/v2.0/token' },
        @{ Field = 'userinfo_endpoint'; Value = 'https://graph.microsoft.com/v1.0/me' },
        @{ Field = 'userinfo_endpoint'; Value = $null }
    ) {
        $script:probeMetadataOverrides[$Field] = $Value
        Assert-ProbeTestFailure DiscoveryMetadata InvalidMetadata 1 ((@{ issuer = 'Issuer'; authorization_endpoint = 'Authorization'; token_endpoint = 'Token'; userinfo_endpoint = 'UserInfo' }[$Field]) + 'Metadata' + $(if ($Value -is [string]) { 'Match' } else { 'String' }))
        Should -Invoke Send-LabProbeRequest -Times 1 -Exactly
    }
    It 'rejects a trailing slash, query, fragment or extra path on every pinned discovery value' -ForEach @(@{Suffix='/'}, @{Suffix='?extra=1'}, @{Suffix='#fragment'}, @{Suffix='/extra'}) {
        foreach ($field in @('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint')) {
            $base = switch ($field) {
                'issuer' { $script:probeAuthority + '/v2.0' }
                'authorization_endpoint' { $script:probeAuthorizeEndpoint }
                'token_endpoint' { $script:probeTokenEndpoint }
                'userinfo_endpoint' { $script:probeUserInfoEndpoint }
            }
            $script:probeMetadataOverrides = @{ $field = $base + $Suffix }
            Assert-ProbeTestFailure DiscoveryMetadata InvalidMetadata 1 ((@{ issuer = 'Issuer'; authorization_endpoint = 'Authorization'; token_endpoint = 'Token'; userinfo_endpoint = 'UserInfo' }[$field]) + 'MetadataMatch')
        }
    }
    It 'rejects invalid status, media type, redirect or JSON at <Stage>' -ForEach @(
        @{ Stage = 'Discovery'; Change = @{ Status = 302; Locations = @('https://example.invalid/discovery') } },
        @{ Stage = 'Discovery'; Change = @{ ContentType = 'text/html' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '{not-json' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '[]' } },
        @{ Stage = 'Discovery'; Change = @{ Body = '{"issuer":"one","ISSUER":"two"}' } },
        @{ Stage = 'Token'; Change = @{ Status = 302; Locations = @('https://example.invalid/token') } },
        @{ Stage = 'Token'; Change = @{ Status = 400 } },
        @{ Stage = 'Token'; Change = @{ ContentType = 'text/html' } },
        @{ Stage = 'Token'; Change = @{ Locations = @('https://example.invalid/unexpected') } },
        @{ Stage = 'Token'; Change = @{ Body = 'null' } },
        @{ Stage = 'Token'; Change = @{ Body = '{"token_type":"Bearer","TOKEN_TYPE":"Bearer"}' } },
        @{ Stage = 'UserInfo'; Change = @{ Status = 302; Locations = @('https://example.invalid/userinfo') } },
        @{ Stage = 'UserInfo'; Change = @{ Status = 401 } },
        @{ Stage = 'UserInfo'; Change = @{ ContentType = 'text/plain' } },
        @{ Stage = 'UserInfo'; Change = @{ Body = '[{"sub":"synthetic-pairwise-subject"}]' } },
        @{ Stage = 'UserInfo'; Change = @{ Body = '{"sub":"one","SUB":"two"}' } }
    ) {
        $script:probeResponseOverrides[$Stage] = $Change
        $predicate = if ($Change.Contains('Status')) { 'ResponseStatus' } elseif ($Change.Contains('ContentType')) { 'ResponseMediaType' } elseif ($Change.Contains('Locations')) { 'ResponseLocations' } elseif ($Change.Body -eq '{not-json') { 'ResponseJsonParse' } elseif ($Change.Body -in @('[]', 'null', '[{"sub":"synthetic-pairwise-subject"}]')) { 'ResponseJsonRootObject' } else { 'ResponseJsonPropertyUnique' }
        Assert-ProbeTestFailure ($Stage + 'Response') InvalidResponse (@{ Discovery = 1; Token = 3; UserInfo = 4 }[$Stage]) $predicate
        @($script:probeRequests | Where-Object { $_.Uri.StartsWith('https://example.invalid') }).Count | Should -Be 0
    }

    It 'rejects interactive pages, unexpected authorization status, or ambiguous location headers' -ForEach @(
        @{ Change = @{ Status = 200; Body = '<form>Consent or interactive login</form>' } },
        @{ Change = @{ Status = 401 } },
        @{ Change = @{ Status = 301 } },
        @{ Change = @{ Status = 307 } },
        @{ Change = @{ Status = 308 } },
        @{ Change = @{ Locations = @() } },
        @{ Change = @{ Locations = @('https://login.microsoftonline.com/common/oauth2/nativeclient', 'https://example.invalid/') } }
    ) {
        $script:probeResponseOverrides.Authorization = $Change
        Assert-ProbeTestFailure AuthorizationResponse InvalidAuthorizationResponse 2 $(if ($Change.Contains('Status')) { 'AuthorizationStatus' } else { 'AuthorizationLocationCount' })
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
    }
    It 'rejects untrusted authorization redirects before forwarding the cookie: <_>' -ForEach @(
        'https://example.invalid/callback', 'http://login.microsoftonline.com/common/oauth2/nativeclient',
        'https://login.microsoftonline.com:444/common/oauth2/nativeclient',
        'https://user@login.microsoftonline.com/common/oauth2/nativeclient',
        'https://login.microsoftonline.com/common/oauth2/nativeclient#fragment',
        'https://login.microsoftonline.com.example.invalid/common/oauth2/nativeclient',
        '//example.invalid/callback', 'file:///tmp/callback', 'https://login.microsoftonline.com/logout',
        'https://login.microsoftonline.com/another-tenant/oauth2/v2.0/authorize'
    ) {
        $script:probeRedirectOverride = $_
        $predicate = switch -Regex ($_) {
            '^(http:|file:)' { 'CallbackScheme'; break }
            '^https://login.microsoftonline.com:444' { 'CallbackPort'; break }
            '^https://user@' { 'CallbackUserInfo'; break }
            '#fragment$' { 'CallbackFragment'; break }
            '^https://login.microsoftonline.com/(logout|another-tenant)' { 'CallbackPath'; break }
            default { 'CallbackHost' }
        }
        Assert-ProbeTestFailure Callback InvalidCallback 2 $predicate
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
    }
    It 'does not follow even a same-origin authorization loop' {
        $script:probeCallbackMode = 'loop'
        Assert-ProbeTestFailure Callback InvalidCallback 2 CallbackPath
        $script:probeAuthorizeCount | Should -Be 1
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
        @($script:probeRequests | Where-Object Method -EQ 'POST').Count | Should -Be 0
    }
    It 'rejects ambiguous, unbound or error callback <_> before token exchange' -ForEach @(
        'missing-state', 'wrong-state', 'empty-state', 'duplicate-state', 'encoded-duplicate-state', 'case-duplicate-state',
        'missing-code', 'empty-code', 'blank-code', 'duplicate-code', 'encoded-duplicate-code', 'case-duplicate-code',
        'oversize-code', 'unnamed-field', 'duplicate-extra-field', 'login-required', 'interaction-required', 'consent-required', 'access-denied'
    ) {
        $script:probeCallbackMode = $_
        $predicate = switch -Regex ($_) {
            'duplicate' { 'CallbackKeyMultiplicity'; break }
            '^(missing|wrong|empty)-state$' { 'CallbackStateMatch'; break }
            '^(missing|empty|blank)-code$' { 'CallbackCodePresent'; break }
            '^oversize-code$' { 'CallbackCodeLength'; break }
            '^unnamed-field$' { 'CallbackKeyName'; break }
            default { 'CallbackErrorAbsent' }
        }
        Assert-ProbeTestFailure Callback InvalidCallback 2 $predicate
        Should -Invoke Send-LabProbeRequest -Times 2 -Exactly
        @($script:probeRequests | Where-Object Method -EQ 'POST').Count | Should -Be 0
    }

    It 'preserves baseline acceptance when the optional returned scope is omitted' {
        $script:probeTokenRemove = @('scope')
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
        $script:probeRequests.Count | Should -Be 4
    }
    It 'preserves baseline acceptance for identity-only returned scope strings' -ForEach @('openid profile', 'profile openid', 'openid') {
        $script:probeTokenOverrides.scope = $_
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
    }
    It 'accepts syntax-valid returned names rejected by the baseline without requesting them: <Case>' -ForEach @(
        @{ Case = 'additional resource name'; Value = 'openid profile User.Read' },
        @{ Case = 'offline_access name only'; Value = 'openid offline_access' },
        @{ Case = 'resource URI'; Value = 'https://graph.microsoft.com/.default' },
        @{ Case = 'uppercase identity name'; Value = 'OPENID' },
        @{ Case = 'mixed case distinct names'; Value = 'openid OpenId OPENID profile Profile' },
        @{ Case = 'duplicate additional names'; Value = 'User.Read User.Read' },
        @{ Case = 'case-distinct resource names'; Value = 'User.Read user.read USER.READ' },
        @{ Case = 'punctuation boundaries'; Value = '!#[]^~ / : ; = ? @' },
        @{ Case = 'long single token'; Value = ('x' * 32768) },
        @{ Case = 'long token list'; Value = (('x ' * 8192) + 'x') }
    ) {
        Assert-ProbeReturnedScopeExpansion $Value
    }
    It 'does not bypass later acceptance gates for a syntax-valid expanded scope: <Case>' -ForEach @(
        @{ Case = 'ID-token structure'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'TokenPartCount'; Setup = { $script:probeIdTokenMode = 'empty' } },
        @{ Case = 'ID-token algorithm'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderAlgorithmMatch'; Setup = { $script:probeHeaderOverrides.alg = 'none' } },
        @{ Case = 'transaction binding'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'NonceClaimMatch'; Setup = { $script:probeClaimsOverrides.nonce = 'wrong-synthetic-nonce' } },
        @{ Case = 'current identity'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'UsernameMatch'; Setup = { $script:probeClaimsOverrides.preferred_username = 'different@example.invalid' } },
        @{ Case = 'freshness'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'ExpiryFuture'; Setup = { $script:probeClaimsOverrides.exp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1 } },
        @{ Case = 'UserInfo response'; Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Requests = 4; Predicate = 'ResponseStatus'; Setup = { $script:probeResponseOverrides.UserInfo = @{ Status = 500 } } },
        @{ Case = 'UserInfo subject'; Phase = 'UserInfoSubject'; Code = 'InvalidUserInfoSubject'; Requests = 4; Predicate = 'UserInfoSubjectMatch'; Setup = { $script:probeUserInfoOverrides.sub = 'different-synthetic-subject' } }
    ) {
        # Intentional ordering difference, so this is candidate-only: the
        # unchanged baseline stops earlier at ScopeAllowedGrammar. The separate
        # expansion helper proves that earlier stop and the shared raw request
        # prefix. Here the exact later failure must emit no partial receipt.
        $script:probeCompareBaseline = $false
        $script:probeTokenOverrides.scope = 'openid profile User.Read'
        & $Setup
        Assert-ProbeTestFailure $Phase $Code $Requests $Predicate
        Should -Invoke Send-LabProbeRequest -Times $Requests -Exactly
        Should -Invoke Send-BaselineLabProbeRequest -Times 0 -Exactly
        $script:probeRequests[0].Uri | Should -BeExactly $script:probeDiscovery
        $script:probeRequests[1].Uri.StartsWith($script:probeAuthorizeEndpoint + '?', [StringComparison]::Ordinal) | Should -BeTrue
        $script:probeRequests[2].Uri | Should -BeExactly $script:probeTokenEndpoint
        $script:probeAuthorizeQuery['scope'] | Should -BeExactly 'openid profile'
        ([Web.HttpUtility]::ParseQueryString($script:probeRequests[2].Body))['scope'] | Should -BeExactly 'openid profile'
        if ($Requests -eq 4) {
            $script:probeRequests[3].Uri | Should -BeExactly $script:probeUserInfoEndpoint
            $script:probeRequests[3].Method | Should -BeExactly 'GET'
            $script:probeRequests[3].Headers.Count | Should -Be 1
            $script:probeRequests[3].Headers.Authorization | Should -BeExactly 'Bearer synthetic-opaque-access-token'
        }
    }
    It 'checks every ASCII code point as a complete returned scope: <CodePoint>' -ForEach @(
        foreach ($codePoint in 0..127) {
            # Independent RFC 6749 ABNF ranges, not the production regex.
            @{ CodePoint = $codePoint; Allowed = ($codePoint -eq 0x21 -or ($codePoint -ge 0x23 -and $codePoint -le 0x5B) -or ($codePoint -ge 0x5D -and $codePoint -le 0x7E)) }
        }
    ) {
        $value = [string][char]$CodePoint
        if ($Allowed) {
            Assert-ProbeReturnedScopeExpansion $value
        } else {
            $script:probeTokenOverrides.scope = $value
            Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 ScopeSyntax
            Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
        }
    }
    It 'rejects malformed returned scope syntax with unchanged baseline decisions: <Case>' -ForEach @(
        @{ Case = 'empty'; Value = '' },
        @{ Case = 'space only'; Value = ' ' },
        @{ Case = 'multiple spaces only'; Value = '  ' },
        @{ Case = 'leading space'; Value = ' openid' },
        @{ Case = 'trailing space'; Value = 'openid ' },
        @{ Case = 'empty middle token'; Value = 'openid  profile' },
        @{ Case = 'leading LF'; Value = "`nopenid" },
        @{ Case = 'trailing LF'; Value = "openid`n" },
        @{ Case = 'embedded LF'; Value = "openid`nprofile" },
        @{ Case = 'trailing CRLF'; Value = "openid`r`n" },
        @{ Case = 'embedded tab'; Value = "openid`tprofile" },
        @{ Case = 'embedded quote'; Value = 'openid"profile' },
        @{ Case = 'embedded backslash'; Value = 'openid\profile' },
        @{ Case = 'first non-ASCII code point'; Value = [string][char]0x0080 },
        @{ Case = 'next-line control'; Value = ('openid' + [char]0x0085) },
        @{ Case = 'last C1 control'; Value = [string][char]0x009F },
        @{ Case = 'nonbreaking space'; Value = ('openid' + [char]0x00A0 + 'profile') },
        @{ Case = 'Latin letter'; Value = ('profil' + [char]0x00E9) },
        @{ Case = 'combining mark'; Value = ('profile' + [char]0x0301) },
        @{ Case = 'em space'; Value = ('openid' + [char]0x2003 + 'profile') },
        @{ Case = 'zero width space'; Value = ('openid' + [char]0x200B) },
        @{ Case = 'line separator'; Value = ('openid' + [char]0x2028) },
        @{ Case = 'paragraph separator'; Value = ('openid' + [char]0x2029) },
        @{ Case = 'BOM'; Value = ([string][char]0xFEFF + 'openid') },
        @{ Case = 'fullwidth ASCII lookalike'; Value = [string][char]0xFF21 },
        @{ Case = 'valid supplementary pair'; Value = [char]::ConvertFromUtf32(0x1F600) },
        @{ Case = 'unicode maximum'; Value = [char]::ConvertFromUtf32(0x10FFFF) }
    ) {
        $script:probeTokenOverrides.scope = $Value
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 ScopeSyntax
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects every ASCII forbidden code point inside a token: <CodePoint>' -ForEach @(
        foreach ($codePoint in @((0..31) + @(34, 92, 127))) { @{ CodePoint = $codePoint } }
    ) {
        $script:probeTokenOverrides.scope = 'openid' + [char]$CodePoint + 'profile'
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 ScopeSyntax
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects present nonstring returned scope instead of coercing it: <Case>' -ForEach @(
        @{ Case = 'null'; Value = $null },
        @{ Case = 'true'; Value = $true },
        @{ Case = 'false'; Value = $false },
        @{ Case = 'zero'; Value = 0 },
        @{ Case = 'integer'; Value = 42 },
        @{ Case = 'fraction'; Value = 1.5 },
        @{ Case = 'empty array'; Value = @() },
        @{ Case = 'one-element array'; Value = @('openid') },
        @{ Case = 'multiple-element array'; Value = @('openid', 'profile') },
        @{ Case = 'empty object'; Value = @{} },
        @{ Case = 'object'; Value = @{ scope = 'openid' } }
    ) {
        $script:probeTokenOverrides.scope = $Value
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 ScopeString
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects malformed UTF-16 returned scope after the parser seam: <Case>' -ForEach @(
        @{ Case = 'lone high surrogate'; Units = @(0xD800) },
        @{ Case = 'lone low surrogate'; Units = @(0xDC00) },
        @{ Case = 'reversed pair'; Units = @(0xDC00, 0xD800) },
        @{ Case = 'two high surrogates'; Units = @(0xD800, 0xDBFF) },
        @{ Case = 'two low surrogates'; Units = @(0xDC00, 0xDFFF) },
        @{ Case = 'high surrogate before ASCII'; Units = @(0xD800, 0x61) },
        @{ Case = 'low surrogate after ASCII'; Units = @(0x61, 0xDFFF) }
    ) {
        # Serializers/parsers may reject or replace lone surrogates themselves.
        # Inject exact UTF-16 units only after the real response parser, into
        # both implementations. This proves the scope guard, not JSON decoding.
        $script:probeMalformedScope = -join @($Units | ForEach-Object { [char]$_ })
        Mock Read-LabProbeResponse {
            param($Response, [hashtable]$Diagnostic)
            $parsed = & $script:probeReadResponseFunction $Response -Diagnostic $Diagnostic
            if ($parsed.Contains('access_token')) { $parsed.scope = $script:probeMalformedScope }
            return $parsed
        }
        Mock Read-BaselineLabProbeResponse {
            param($Response, [hashtable]$Diagnostic)
            $parsed = & $script:probeBaselineReadResponseFunction $Response -Diagnostic $Diagnostic
            if ($parsed.Contains('access_token')) { $parsed.scope = $script:probeMalformedScope }
            return $parsed
        }
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 ScopeSyntax
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }

    It 'requires each token response field: <_>' -ForEach @('id_token', 'access_token', 'token_type') {
        $script:probeTokenRemove = @($_)
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 (@{ token_type = 'TokenTypeString'; access_token = 'AccessTokenString'; id_token = 'IdTokenString' }[$_])
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects malformed token response <Field>' -ForEach @(
        @{ Field = 'token_type'; Value = 'PoP' }, @{ Field = 'token_type'; Value = @('Bearer') },
        @{ Field = 'access_token'; Value = '' }, @{ Field = 'access_token'; Value = ' ' },
        @{ Field = 'access_token'; Value = "token`r`nInjected: value" }, @{ Field = 'access_token'; Value = @('token') },
        @{ Field = 'id_token'; Value = @('header.payload.signature') }, @{ Field = 'id_token'; Value = $null },
        @{ Field = 'refresh_token'; Value = 'unrequested-refresh-token' }
    ) {
        $script:probeTokenOverrides[$Field] = $Value
        $predicate = switch ($Field) {
            'token_type' { if ($Value -is [string]) { 'TokenTypeBearer' } else { 'TokenTypeString' } }
            'access_token' { if ($Value -isnot [string]) { 'AccessTokenString' } elseif ([string]::IsNullOrWhiteSpace($Value)) { 'AccessTokenNonblank' } else { 'AccessTokenNoNewline' } }
            'id_token' { 'IdTokenString' }
            'refresh_token' { 'RefreshTokenFalsey' }
        }
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 $predicate
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects an opaque or malformed ID token: <_>' -ForEach @(
        'opaque', 'empty', 'two-parts', 'four-parts', 'empty-header', 'empty-payload',
        'invalid-header-alphabet', 'invalid-payload-alphabet', 'invalid-header-length', 'invalid-payload-length',
        'invalid-header-utf8', 'invalid-payload-utf8', 'empty-signature', 'invalid-signature-alphabet'
    ) {
        $script:probeIdTokenMode = $_
        $predicate = switch -Regex ($_) {
            '^(opaque|empty|two-parts|four-parts)$' { 'TokenPartCount'; break }
            '^(empty-header|invalid-header-alphabet)$' { 'HeaderAlphabet'; break }
            '^(empty-payload|invalid-payload-alphabet)$' { 'ClaimsAlphabet'; break }
            '^invalid-header-length$' { 'HeaderLength'; break }
            '^invalid-payload-length$' { 'ClaimsLength'; break }
            '^invalid-header-utf8$' { 'HeaderUtf8Decode'; break }
            '^invalid-payload-utf8$' { 'ClaimsUtf8Decode'; break }
            default { 'SignatureAlphabet' }
        }
        Assert-ProbeTestFailure TokenEncoding InvalidTokenEncoding 3 $predicate
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects unexpected ID-token algorithms: <_>' -ForEach @('none', 'HS256', 'rs256', '', @('RS256')) {
        $script:probeHeaderOverrides.alg = $_
        Assert-ProbeTestFailure TokenEncoding InvalidTokenEncoding 3 $(if ($_ -is [string]) { 'HeaderAlgorithmMatch' } else { 'HeaderAlgorithmString' })
    }
    It 'rejects unsupported critical header extensions' -ForEach @(@('custom'), 'custom', $null) {
        $script:probeHeaderOverrides.crit = $_
        Assert-ProbeTestFailure TokenEncoding InvalidTokenEncoding 3 HeaderCriticalAbsent
    }
    It 'rejects malformed, non-object or duplicate header/claim JSON: <Part>' -ForEach @(
        @{ Part = 'Header'; Json = '{broken' }, @{ Part = 'Header'; Json = '[]' },
        @{ Part = 'Header'; Json = '{"alg":"RS256","ALG":"RS256"}' },
        @{ Part = 'Claims'; Json = '{broken' }, @{ Part = 'Claims'; Json = '[]' },
        @{ Part = 'Claims'; Json = '{"iss":"one","ISS":"two"}' }
    ) {
        if ($Part -eq 'Header') { $script:probeRawHeader = $Json } else { $script:probeRawClaims = $Json }
        Assert-ProbeTestFailure TokenEncoding InvalidTokenEncoding 3 ($Part + 'Json' + $(if ($Json -eq '{broken') { 'Parse' } elseif ($Json -eq '[]') { 'RootObject' } else { 'PropertyUnique' }))
    }
    It 'requires all identity, transaction and time claims: <_>' -ForEach @('iss', 'tid', 'aud', 'nonce', 'oid', 'preferred_username', 'sub', 'iat', 'exp') {
        $script:probeClaimsRemove = @($_)
        Assert-ProbeTestFailure $(if ($_ -in @('iat', 'exp')) { 'TokenTimes' } else { 'TokenBinding' }) $(if ($_ -in @('iat', 'exp')) { 'InvalidTokenTimes' } else { 'InvalidTokenBinding' }) 3 (@{ iss = 'IssuerClaimString'; tid = 'TenantClaimString'; aud = 'AudienceClaimString'; nonce = 'NonceClaimString'; oid = 'ObjectIdString'; preferred_username = 'UsernameString'; sub = 'SubjectString'; iat = 'IssuedAtInteger'; exp = 'ExpiryInteger' }[$_])
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects incorrectly bound or non-string identity claims: <Field>' -ForEach @(
        @{ Field = 'iss'; Value = 'https://login.microsoftonline.com/common/v2.0' },
        @{ Field = 'iss'; Value = @('https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0') },
        @{ Field = 'tid'; Value = '44444444-4444-4444-8444-444444444444' },
        @{ Field = 'tid'; Value = @('11111111-1111-4111-8111-111111111111') },
        @{ Field = 'aud'; Value = '44444444-4444-4444-8444-444444444444' },
        @{ Field = 'aud'; Value = @('22222222-2222-4222-8222-222222222222') },
        @{ Field = 'nonce'; Value = 'replayed-from-another-transaction' }, @{ Field = 'nonce'; Value = @('nonce') },
        @{ Field = 'azp'; Value = '44444444-4444-4444-8444-444444444444' }, @{ Field = 'azp'; Value = @('22222222-2222-4222-8222-222222222222') },
        @{ Field = 'oid'; Value = '' }, @{ Field = 'oid'; Value = '00000000-0000-0000-0000-000000000000' },
        @{ Field = 'oid'; Value = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, @{ Field = 'oid'; Value = @('33333333-3333-4333-8333-333333333333') },
        @{ Field = 'preferred_username'; Value = 'someone-else@example.invalid' }, @{ Field = 'preferred_username'; Value = @('fixture@example.invalid') },
        @{ Field = 'sub'; Value = '' }, @{ Field = 'sub'; Value = ' ' }, @{ Field = 'sub'; Value = @('synthetic-pairwise-subject') }
    ) {
        $script:probeClaimsOverrides[$Field] = $Value
        $prefix = @{ iss = 'IssuerClaim'; tid = 'TenantClaim'; aud = 'AudienceClaim'; nonce = 'NonceClaim'; azp = 'AuthorizedParty'; oid = 'ObjectId'; preferred_username = 'Username'; sub = 'Subject' }[$Field]
        $suffix = if ($Value -isnot [string]) { 'String' } elseif ($Field -eq 'oid') { if ($Value -eq '00000000-0000-0000-0000-000000000000') { 'Nonzero' } else { 'Format' } } elseif ($Field -eq 'sub') { 'Nonblank' } else { 'Match' }
        Assert-ProbeTestFailure TokenBinding InvalidTokenBinding 3 ($prefix + $suffix)
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects non-integer numeric-date claims: <Field>' -ForEach @(
        @{ Field = 'iat'; Value = '1770000000' }, @{ Field = 'iat'; Value = 1.5 }, @{ Field = 'iat'; Value = $true },
        @{ Field = 'exp'; Value = '1770000600' }, @{ Field = 'exp'; Value = 1.5 }, @{ Field = 'exp'; Value = @([long]1770000600) },
        @{ Field = 'nbf'; Value = '1770000000' }, @{ Field = 'nbf'; Value = 1.5 }, @{ Field = 'nbf'; Value = $null }
    ) {
        $script:probeClaimsOverrides[$Field] = $Value
        Assert-ProbeTestFailure TokenTimes InvalidTokenTimes 3 (@{ iat = 'IssuedAtInteger'; exp = 'ExpiryInteger'; nbf = 'NotBeforeInteger' }[$Field])
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects expired, stale, future or internally inconsistent token times: <_>' -ForEach @('expired', 'stale-iat', 'future-iat', 'future-nbf', 'exp-before-iat', 'exp-equals-iat') {
        $timeCase = $_
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        switch ($timeCase) {
            'expired' { $script:probeClaimsOverrides.exp = $now - 10 }
            'stale-iat' { $script:probeClaimsOverrides.iat = $now - 600 }
            'future-iat' { $script:probeClaimsOverrides.iat = $now + 300 }
            'future-nbf' { $script:probeClaimsOverrides.nbf = $now + 300 }
            'exp-before-iat' { $script:probeClaimsOverrides.iat = $now + 30; $script:probeClaimsOverrides.exp = $now + 20 }
            'exp-equals-iat' { $script:probeClaimsOverrides.iat = $now + 30; $script:probeClaimsOverrides.exp = $now + 30 }
        }
        Assert-ProbeTestFailure TokenTimes InvalidTokenTimes 3 (@{ expired = 'ExpiryFuture'; 'stale-iat' = 'IssuedAtRecent'; 'future-iat' = 'IssuedAtNotFuture'; 'future-nbf' = 'NotBeforeNotFuture'; 'exp-before-iat' = 'ExpiryAfterIssuedAt'; 'exp-equals-iat' = 'ExpiryAfterIssuedAt' }[$timeCase])
        Should -Invoke Send-LabProbeRequest -Times 3 -Exactly
    }
    It 'rejects UserInfo subject mismatch or malformed subject: <_>' -ForEach @('wrong-subject', 'SYNTHETIC-PAIRWISE-SUBJECT', '', ' ', @('synthetic-pairwise-subject'), $null) {
        $script:probeUserInfoOverrides.sub = $_
        Assert-ProbeTestFailure UserInfoSubject InvalidUserInfoSubject 4 $(if ($_ -is [string]) { 'UserInfoSubjectMatch' } else { 'UserInfoSubjectString' })
        Should -Invoke Send-LabProbeRequest -Times 4 -Exactly
    }
    It 'rejects missing UserInfo subject even when another user field matches' {
        $script:probeUserInfoRemove = @('sub')
        $script:probeUserInfoOverrides.preferred_username = 'fixture@example.invalid'
        Assert-ProbeTestFailure UserInfoSubject InvalidUserInfoSubject 4 UserInfoSubjectString
    }
    It 'suppresses secret-bearing transport details and emits no partial receipt: <_>' -ForEach @('Discovery', 'Authorization', 'Token', 'UserInfo') {
        $script:probeThrowStage = $_
        Assert-ProbeTestFailure ($_ + 'Request') UnexpectedFailure (@{ Discovery = 1; Authorization = 2; Token = 3; UserInfo = 4 }[$_]) RequestInvocation
    }
    It 'suppresses synthetic nested constructor/disposal-style errors at the public request boundary: <Stage> <Kind>' -ForEach @(
        @{ Stage = 'Discovery'; Kind = 'construction'; Requests = 1 },
        @{ Stage = 'Discovery'; Kind = 'disposal'; Requests = 1 },
        @{ Stage = 'Discovery'; Kind = 'error-record'; Requests = 1 },
        @{ Stage = 'Authorization'; Kind = 'construction'; Requests = 2 },
        @{ Stage = 'Authorization'; Kind = 'disposal'; Requests = 2 },
        @{ Stage = 'Authorization'; Kind = 'error-record'; Requests = 2 },
        @{ Stage = 'Token'; Kind = 'construction'; Requests = 3 },
        @{ Stage = 'Token'; Kind = 'disposal'; Requests = 3 },
        @{ Stage = 'Token'; Kind = 'error-record'; Requests = 3 },
        @{ Stage = 'UserInfo'; Kind = 'construction'; Requests = 4 },
        @{ Stage = 'UserInfo'; Kind = 'disposal'; Requests = 4 },
        @{ Stage = 'UserInfo'; Kind = 'error-record'; Requests = 4 }
    ) {
        # This proves public-boundary sanitization, not actual constructor or
        # Dispose runtime behavior. The native transport is not loaded here.
        $inner = [InvalidOperationException]::new('diagnostic-secret-inner https://diagnostic-secret.invalid/?token=diagnostic-secret')
        $exception = if ($Kind -eq 'disposal') {
            [ObjectDisposedException]::new('diagnostic-secret-disposal', $inner)
        } else { [InvalidOperationException]::new('diagnostic-secret-construction', $inner) }
        $exception.Data['diagnostic-secret-key'] = 'diagnostic-secret-data'
        $script:probeException = $exception
        if ($Kind -eq 'error-record') {
            $script:probeException = [Management.Automation.ErrorRecord]::new($exception, 'diagnostic-secret-id',
                [Management.Automation.ErrorCategory]::InvalidOperation, 'diagnostic-secret-target')
            $script:probeException.ErrorDetails = [Management.Automation.ErrorDetails]::new('diagnostic-secret-details')
        }
        $script:probeThrowStage = $Stage
        Assert-ProbeTestFailure ($Stage + 'Request') UnexpectedFailure $Requests RequestInvocation
    }
    It 'uses UnexpectedFailure for local request construction before HTTP: <Phase>' -ForEach @(
        @{ Phase = 'AuthorizationRequest'; FailureCall = 1; Requests = 1 },
        @{ Phase = 'TokenRequest'; FailureCall = 2; Requests = 2 }
    ) {
        # Only candidate helper execution is fault-injected; protocol equivalence is tested separately.
        $script:probeCompareBaseline = $false
        $script:probeFormCalls = 0
        $script:probeFormFailureCall = $FailureCall
        Mock ConvertTo-LabProbeForm {
            param($Values)
            $script:probeFormCalls++
            if ($script:probeFormCalls -eq $script:probeFormFailureCall) {
                throw [InvalidOperationException]::new('diagnostic-secret-form', [Exception]::new('diagnostic-secret-inner'))
            }
            & $script:probeFormFunction $Values
        }
        Assert-ProbeTestFailure $Phase UnexpectedFailure $Requests $(if ($FailureCall -eq 1) { 'AuthorizationFormCreation' } else { 'TokenFormCreation' })
        $script:probeFormCalls | Should -Be $FailureCall
    }
    It 'does not retain a prior successful validation code during transaction construction' {
        # Fault-injected helper, not a changed protocol fixture.
        $script:probeCompareBaseline = $false
        Mock ConvertTo-LabProbeBase64Url { throw 'diagnostic-secret-random' }
        Assert-ProbeTestFailure AuthorizationRequest UnexpectedFailure 1 StateCreation
    }
    It 'never emits secret markers from protocol inputs: <Case>' -ForEach @(
        @{ Case = 'configuration'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0 },
        @{ Case = 'cookie'; Phase = 'Cookie'; Code = 'InvalidCookie'; Requests = 0 },
        @{ Case = 'discovery-url'; Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Requests = 1 },
        @{ Case = 'discovery-body'; Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Requests = 1 },
        @{ Case = 'authorization-body'; Phase = 'AuthorizationResponse'; Code = 'InvalidAuthorizationResponse'; Requests = 2 },
        @{ Case = 'callback-header'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2 },
        @{ Case = 'malformed-callback'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2 },
        @{ Case = 'token-body'; Phase = 'TokenResponse'; Code = 'InvalidResponse'; Requests = 3 },
        @{ Case = 'token-scope'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3 },
        @{ Case = 'token-header'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3 },
        @{ Case = 'token-claims'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3 },
        @{ Case = 'userinfo-body'; Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Requests = 4 },
        @{ Case = 'userinfo-subject'; Phase = 'UserInfoSubject'; Code = 'InvalidUserInfoSubject'; Requests = 4 }
    ) {
        switch ($Case) {
            'configuration' { $script:probeArguments.ExpectedUpn = 'diagnostic-secret-invalid-upn' }
            'cookie' { $script:probeArguments.Cookie = 'diagnostic-secret-cookie;invalid' }
            'discovery-url' { $script:probeMetadataOverrides.issuer = 'https://diagnostic-secret.invalid/?id=diagnostic-secret' }
            'discovery-body' { $script:probeResponseOverrides.Discovery = @{ Body = '{"diagnostic-secret":' } }
            'authorization-body' { $script:probeResponseOverrides.Authorization = @{ Status = 200; Body = '<form>diagnostic-secret</form>' } }
            'callback-header' { $script:probeResponseOverrides.Authorization = @{ Locations = @('https://diagnostic-secret.invalid/?code=diagnostic-secret'); Body = 'diagnostic-secret-body' } }
            'malformed-callback' { $script:probeRedirectOverride = 'https://[diagnostic-secret' }
            'token-body' { $script:probeResponseOverrides.Token = @{ Body = '{"access_token":"diagnostic-secret","ACCESS_TOKEN":"diagnostic-secret"}' } }
            'token-scope' { $script:probeTokenOverrides.scope = "diagnostic-secret-scope`n" }
            'token-header' { $script:probeHeaderOverrides.alg = 'diagnostic-secret-algorithm' }
            'token-claims' { $script:probeClaimsOverrides.preferred_username = 'diagnostic-secret@example.invalid' }
            'userinfo-body' { $script:probeResponseOverrides.UserInfo = @{ Body = '["diagnostic-secret"]' } }
            'userinfo-subject' { $script:probeUserInfoOverrides.sub = 'diagnostic-secret-subject' }
        }
        $predicate = @{ configuration = 'UpnFormat'; cookie = 'CookieAlphabet'; 'discovery-url' = 'IssuerMetadataMatch'; 'discovery-body' = 'ResponseJsonParse'; 'authorization-body' = 'AuthorizationStatus'; 'callback-header' = 'CallbackHost'; 'malformed-callback' = 'CallbackUriConstruction'; 'token-body' = 'ResponseJsonPropertyUnique'; 'token-scope' = 'ScopeSyntax'; 'token-header' = 'HeaderAlgorithmMatch'; 'token-claims' = 'UsernameMatch'; 'userinfo-body' = 'ResponseJsonRootObject'; 'userinfo-subject' = 'UserInfoSubjectMatch' }[$Case]
        Assert-ProbeTestFailure $Phase $Code $Requests $predicate
    }

    It 'preserves baseline acceptance for case-insensitive bearer type and duplicate identity-only scopes' -ForEach @('profile', 'openid openid', 'openid openid profile', 'profile profile openid') {
        $script:probeTokenOverrides = @{ token_type = 'bEaReR'; scope = $_ }
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
    }
    It 'preserves falsey refresh_token compatibility without requesting refresh permission' -ForEach @(
        @{ Value = $null }, @{ Value = $false }, @{ Value = 0 }, @{ Value = '' }, @{ Value = @() }
    ) {
        $script:probeTokenOverrides.refresh_token = $Value
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
        $script:probeRequests[2].Body | Should -Not -Match 'refresh_token|offline_access'
    }
    It 'still rejects truthy refresh_token values irrespective of type' -ForEach @(@{ Value = $true }, @{ Value = 1 }, @{ Value = '0' }, @{ Value = @{ unrequested = 'value' } }) {
        $script:probeTokenOverrides.refresh_token = $Value
        Assert-ProbeTestFailure TokenResponse InvalidTokenResponse 3 RefreshTokenFalsey
    }
    It 'preserves ignored JWT metadata and signature alphabet-only acceptance' {
        $script:probeHeaderOverrides = @{ typ = 'not-enforced-by-this-bounded-probe'; kid = $null }
        $script:probeSignature = 'a'
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
    }
    It 'preserves exact boundary lengths for cookie, expected UPN and callback code' -ForEach @('cookie', 'upn', 'code') {
        switch ($_) {
            'cookie' { $script:probeArguments.Cookie = 'x' * 32768 }
            'upn' {
                $script:probeArguments.ExpectedUpn = ('x' * 304) + '@example.invalid'
                $script:probeClaimsOverrides.preferred_username = $script:probeArguments.ExpectedUpn
            }
            'code' { $script:probeCallbackMode = 'boundary-code' }
        }
        (Invoke-ProbeTest).ServerBackedSessionReuse | Should -BeTrue
    }
    It 'rejects wrong types independently at every metadata guard: <Field>' -ForEach @(
        @{ Field = 'issuer'; Predicate = 'IssuerMetadataString' },
        @{ Field = 'authorization_endpoint'; Predicate = 'AuthorizationMetadataString' },
        @{ Field = 'token_endpoint'; Predicate = 'TokenMetadataString' },
        @{ Field = 'userinfo_endpoint'; Predicate = 'UserInfoMetadataString' }
    ) {
        $script:probeMetadataOverrides[$Field] = @('synthetic-wrong-type')
        Assert-ProbeTestFailure DiscoveryMetadata InvalidMetadata 1 $Predicate
    }
    It 'keeps every JSON response envelope guard ordered at <Stage>: <Predicate>' -ForEach @(
        @{ Stage = 'Discovery'; Requests = 1 }, @{ Stage = 'Token'; Requests = 3 }, @{ Stage = 'UserInfo'; Requests = 4 }
    ) {
        foreach ($case in @(
            @{ Change = @{ Status = 400; ContentType = 'text/plain'; Locations = @('https://example.invalid'); Body = '{broken' }; Predicate = 'ResponseStatus' },
            @{ Change = @{ ContentType = 'Application/Json'; Locations = @('https://example.invalid'); Body = '{broken' }; Predicate = 'ResponseMediaType' },
            @{ Change = @{ Locations = @('https://example.invalid'); Body = '{broken' }; Predicate = 'ResponseLocations' },
            @{ Change = @{ Body = '{broken' }; Predicate = 'ResponseJsonParse' },
            @{ Change = @{ Body = 'null' }; Predicate = 'ResponseJsonRootObject' },
            @{ Change = @{ Body = '{"first":1,"FIRST":2}' }; Predicate = 'ResponseJsonPropertyUnique' }
        )) {
            $script:probeAuthorizeQuery = $null
            $script:probeResponseOverrides[$Stage] = $case.Change
            Assert-ProbeTestFailure ($Stage + 'Response') InvalidResponse $Requests $case.Predicate
        }
    }
    It 'returns the original first-failing predicate when several checks fail: <Case>' -ForEach @(
        @{ Case = 'tenant format before zero client and UPN'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0; Predicate = 'TenantFormat'; Setup = { $script:probeArguments.TenantId = 'BAD'; $script:probeArguments.ClientId = '00000000-0000-0000-0000-000000000000'; $script:probeArguments.ExpectedUpn = '' } },
        @{ Case = 'tenant nonzero before client format'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0; Predicate = 'TenantNonzero'; Setup = { $script:probeArguments.TenantId = '00000000-0000-0000-0000-000000000000'; $script:probeArguments.ClientId = 'BAD' } },
        @{ Case = 'client format before UPN'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0; Predicate = 'ClientFormat'; Setup = { $script:probeArguments.ClientId = 'BAD'; $script:probeArguments.ExpectedUpn = '' } },
        @{ Case = 'client nonzero before UPN'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0; Predicate = 'ClientNonzero'; Setup = { $script:probeArguments.ClientId = '00000000-0000-0000-0000-000000000000'; $script:probeArguments.ExpectedUpn = '' } },
        @{ Case = 'UPN length before format'; Phase = 'Configuration'; Code = 'InvalidConfiguration'; Requests = 0; Predicate = 'UpnLength'; Setup = { $script:probeArguments.ExpectedUpn = ' ' * 321 } },
        @{ Case = 'cookie name before length and alphabet'; Phase = 'Cookie'; Code = 'InvalidCookie'; Requests = 0; Predicate = 'CookieName'; Setup = { $script:probeArguments.CookieName = 'bad'; $script:probeArguments.Cookie = ' ' * 32769 } },
        @{ Case = 'cookie length before alphabet'; Phase = 'Cookie'; Code = 'InvalidCookie'; Requests = 0; Predicate = 'CookieLength'; Setup = { $script:probeArguments.Cookie = ' ' * 32769 } },
        @{ Case = 'issuer metadata type before all later fields'; Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Requests = 1; Predicate = 'IssuerMetadataString'; Setup = { $script:probeMetadataOverrides = @{ issuer = @('bad'); authorization_endpoint = $null; token_endpoint = $null; userinfo_endpoint = $null } } },
        @{ Case = 'issuer metadata match before authorization'; Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Requests = 1; Predicate = 'IssuerMetadataMatch'; Setup = { $script:probeMetadataOverrides = @{ issuer = 'bad'; authorization_endpoint = $null } } },
        @{ Case = 'authorization metadata before token'; Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Requests = 1; Predicate = 'AuthorizationMetadataMatch'; Setup = { $script:probeMetadataOverrides = @{ authorization_endpoint = 'bad'; token_endpoint = $null } } },
        @{ Case = 'token metadata before UserInfo'; Phase = 'DiscoveryMetadata'; Code = 'InvalidMetadata'; Requests = 1; Predicate = 'TokenMetadataMatch'; Setup = { $script:probeMetadataOverrides = @{ token_endpoint = 'bad'; userinfo_endpoint = $null } } },
        @{ Case = 'authorization status before locations'; Phase = 'AuthorizationResponse'; Code = 'InvalidAuthorizationResponse'; Requests = 2; Predicate = 'AuthorizationStatus'; Setup = { $script:probeResponseOverrides.Authorization = @{ Status = 200; Locations = @() } } },
        @{ Case = 'callback scheme before host port userinfo fragment path'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackScheme'; Setup = { $script:probeRedirectOverride = 'http://user@example.invalid:444/wrong#fragment' } },
        @{ Case = 'callback host before port userinfo fragment path'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackHost'; Setup = { $script:probeRedirectOverride = 'https://user@example.invalid:444/wrong#fragment' } },
        @{ Case = 'callback port before userinfo fragment path'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackPort'; Setup = { $script:probeRedirectOverride = 'https://user@login.microsoftonline.com:444/wrong#fragment' } },
        @{ Case = 'callback userinfo before fragment path'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackUserInfo'; Setup = { $script:probeRedirectOverride = 'https://user@login.microsoftonline.com/wrong#fragment' } },
        @{ Case = 'callback fragment before path'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackFragment'; Setup = { $script:probeRedirectOverride = 'https://login.microsoftonline.com/wrong#fragment' } },
        @{ Case = 'callback duplicate before error and binding'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackKeyMultiplicity'; Setup = { $script:probeRedirectOverride = $script:probeRedirect + '?code=one&code=two&error=login_required&state=wrong' } },
        @{ Case = 'callback unnamed field before binding'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackKeyName'; Setup = { $script:probeRedirectOverride = $script:probeRedirect + '?unkeyed&state=wrong' } },
        @{ Case = 'callback error before state and code'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackErrorAbsent'; Setup = { $script:probeRedirectOverride = $script:probeRedirect + '?error=login_required&state=wrong&code=' } },
        @{ Case = 'callback state before blank code'; Phase = 'Callback'; Code = 'InvalidCallback'; Requests = 2; Predicate = 'CallbackStateMatch'; Setup = { $script:probeRedirectOverride = $script:probeRedirect + '?state=wrong&code=' } },
        @{ Case = 'token type type before every token guard'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'TokenTypeString'; Setup = { $script:probeTokenOverrides = @{ token_type = @('PoP'); access_token = $null; id_token = $null; refresh_token = $true; scope = $null } } },
        @{ Case = 'token type bearer before access token'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'TokenTypeBearer'; Setup = { $script:probeTokenOverrides = @{ token_type = 'PoP'; access_token = $null } } },
        @{ Case = 'access token type before id token'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'AccessTokenString'; Setup = { $script:probeTokenOverrides = @{ access_token = @(''); id_token = $null } } },
        @{ Case = 'access token blank before newline'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'AccessTokenNonblank'; Setup = { $script:probeTokenOverrides = @{ access_token = "`r`n"; id_token = $null } } },
        @{ Case = 'access token newline before id token'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'AccessTokenNoNewline'; Setup = { $script:probeTokenOverrides = @{ access_token = "token`r`n"; id_token = $null } } },
        @{ Case = 'id token type before refresh token'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'IdTokenString'; Setup = { $script:probeTokenOverrides = @{ id_token = $null; refresh_token = $true } } },
        @{ Case = 'refresh token before scope'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'RefreshTokenFalsey'; Setup = { $script:probeTokenOverrides = @{ refresh_token = $true; scope = $null } } },
        @{ Case = 'scope type before token encoding'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'ScopeString'; Setup = { $script:probeTokenOverrides.scope = @('openid'); $script:probeIdTokenMode = 'empty' } },
        @{ Case = 'scope syntax before token encoding'; Phase = 'TokenResponse'; Code = 'InvalidTokenResponse'; Requests = 3; Predicate = 'ScopeSyntax'; Setup = { $script:probeTokenOverrides.scope = "openid`n"; $script:probeIdTokenMode = 'empty' } },
        @{ Case = 'header alphabet before length claims signature'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderAlphabet'; Setup = { $script:probeTokenOverrides.id_token = '!.!.!' } },
        @{ Case = 'header length before claims'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderLength'; Setup = { $script:probeTokenOverrides.id_token = 'a.!.!' } },
        @{ Case = 'header JSON before claims'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderJsonParse'; Setup = { $script:probeRawHeader = '{broken'; $script:probeRawClaims = '{broken' } },
        @{ Case = 'claims JSON before header algorithm'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'ClaimsJsonParse'; Setup = { $script:probeHeaderOverrides.alg = $null; $script:probeRawClaims = '{broken' } },
        @{ Case = 'header algorithm type before crit signature'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderAlgorithmString'; Setup = { $script:probeHeaderOverrides = @{ alg = $null; crit = $null }; $script:probeSignature = '!' } },
        @{ Case = 'header algorithm match before crit signature'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderAlgorithmMatch'; Setup = { $script:probeHeaderOverrides = @{ alg = 'none'; crit = $null }; $script:probeSignature = '!' } },
        @{ Case = 'critical header before signature'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Requests = 3; Predicate = 'HeaderCriticalAbsent'; Setup = { $script:probeHeaderOverrides.crit = $null; $script:probeSignature = '!' } },
        @{ Case = 'issuer before audience tenant nonce'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'IssuerClaimMatch'; Setup = { $script:probeClaimsOverrides = @{ iss = 'bad'; aud = $null; tid = $null; nonce = $null } } },
        @{ Case = 'audience before tenant nonce'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'AudienceClaimMatch'; Setup = { $script:probeClaimsOverrides = @{ aud = 'bad'; tid = $null; nonce = $null } } },
        @{ Case = 'tenant before nonce'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'TenantClaimMatch'; Setup = { $script:probeClaimsOverrides = @{ tid = 'bad'; nonce = $null } } },
        @{ Case = 'nonce before authorized party'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'NonceClaimMatch'; Setup = { $script:probeClaimsOverrides = @{ nonce = 'bad'; azp = $null } } },
        @{ Case = 'authorized party type before identity'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'AuthorizedPartyString'; Setup = { $script:probeClaimsOverrides = @{ azp = $null; oid = $null } } },
        @{ Case = 'authorized party match before identity'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'AuthorizedPartyMatch'; Setup = { $script:probeClaimsOverrides = @{ azp = 'bad'; oid = $null } } },
        @{ Case = 'object identity type before username'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'ObjectIdString'; Setup = { $script:probeClaimsOverrides = @{ oid = $null; preferred_username = $null } } },
        @{ Case = 'object identity format before username'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'ObjectIdFormat'; Setup = { $script:probeClaimsOverrides = @{ oid = 'bad'; preferred_username = $null } } },
        @{ Case = 'object identity nonzero before username'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'ObjectIdNonzero'; Setup = { $script:probeClaimsOverrides = @{ oid = '00000000-0000-0000-0000-000000000000'; preferred_username = $null } } },
        @{ Case = 'username type before subject'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'UsernameString'; Setup = { $script:probeClaimsOverrides = @{ preferred_username = $null; sub = $null } } },
        @{ Case = 'username match before subject'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'UsernameMatch'; Setup = { $script:probeClaimsOverrides = @{ preferred_username = 'other@example.invalid'; sub = $null } } },
        @{ Case = 'subject type before numeric dates'; Phase = 'TokenBinding'; Code = 'InvalidTokenBinding'; Requests = 3; Predicate = 'SubjectString'; Setup = { $script:probeClaimsOverrides = @{ sub = $null; iat = $null; exp = $null } } },
        @{ Case = 'issued at type before expiry type'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'IssuedAtInteger'; Setup = { $script:probeClaimsOverrides = @{ iat = $null; exp = $null; nbf = $null } } },
        @{ Case = 'expiry type before issued at freshness'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'ExpiryInteger'; Setup = { $script:probeClaimsOverrides = @{ iat = 0; exp = $null } } },
        @{ Case = 'expiry future before issued at future'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'ExpiryFuture'; Setup = { $script:probeClaimsOverrides = @{ iat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 300; exp = 0; nbf = $null } } },
        @{ Case = 'issued at future before expiry relation'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'IssuedAtNotFuture'; Setup = { $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $script:probeClaimsOverrides = @{ iat = $now + 300; exp = $now + 200; nbf = $null } } },
        @{ Case = 'issued at recent before nbf type'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'IssuedAtRecent'; Setup = { $script:probeClaimsOverrides = @{ iat = 0; nbf = $null } } },
        @{ Case = 'expiry relation before nbf type'; Phase = 'TokenTimes'; Code = 'InvalidTokenTimes'; Requests = 3; Predicate = 'ExpiryAfterIssuedAt'; Setup = { $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $script:probeClaimsOverrides = @{ iat = $now + 30; exp = $now + 20; nbf = $null } } }
    ) {
        & $Setup
        Assert-ProbeTestFailure $Phase $Code $Requests $Predicate
    }


    It 'reports each local entropy or challenge operation, not the previously successful operation: <Predicate>' -ForEach @(
        @{ FailureCall = 1; Predicate = 'StateCreation' }, @{ FailureCall = 2; Predicate = 'NonceCreation' },
        @{ FailureCall = 3; Predicate = 'VerifierCreation' }, @{ FailureCall = 4; Predicate = 'ChallengeCreation' }
    ) {
        # This is deliberate helper fault injection, not protocol-equivalence evidence.
        $script:probeCompareBaseline = $false
        $script:probeBase64Calls = 0; $script:probeBase64FailureCall = $FailureCall
        Mock ConvertTo-LabProbeBase64Url {
            param([byte[]]$Bytes)
            $script:probeBase64Calls++
            if ($script:probeBase64Calls -eq $script:probeBase64FailureCall) { throw 'diagnostic-secret-entropy-or-challenge' }
            & $script:probeBase64Function $Bytes
        }
        Assert-ProbeTestFailure AuthorizationRequest UnexpectedFailure 1 $Predicate
        $script:probeBase64Calls | Should -Be $FailureCall
    }
    It 'reports an entered configuration helper failure without claiming a rejected guard' {
        $script:probeCompareBaseline = $false
        Mock Assert-LabProbeConfiguration { throw 'diagnostic-secret-configuration-operation' }
        Assert-ProbeTestFailure Configuration UnexpectedFailure 0 ConfigurationValidation
    }
    It 'classifies JSON conversion-depth failures without leaking nested response data: <Context>' -ForEach @(
        @{ Context = 'Discovery'; Phase = 'DiscoveryResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion'; Requests = 1 },
        @{ Context = 'Token'; Phase = 'TokenResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion'; Requests = 3 },
        @{ Context = 'UserInfo'; Phase = 'UserInfoResponse'; Code = 'InvalidResponse'; Predicate = 'ResponseJsonConversion'; Requests = 4 },
        @{ Context = 'Header'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'HeaderJsonConversion'; Requests = 3 },
        @{ Context = 'Claims'; Phase = 'TokenEncoding'; Code = 'InvalidTokenEncoding'; Predicate = 'ClaimsJsonConversion'; Requests = 3 }
    ) {
        # JsonDocument accepts this depth; the pre-existing ConvertFrom-Json
        # maximum of 16 rejects it. No parser setting or acceptance rule changes.
        $nested = ('{"nested":' * 20) + '"diagnostic-secret-depth"' + ('}' * 20)
        if ($Context -eq 'Header') { $script:probeRawHeader = $nested }
        elseif ($Context -eq 'Claims') { $script:probeRawClaims = $nested }
        else { $script:probeResponseOverrides[$Context] = @{ Body = $nested } }
        Assert-ProbeTestFailure $Phase $Code $Requests $Predicate
    }
    It 'rejects a poisoned diagnostic container rather than coercing it to a tuple' -ForEach @(
        @{ Value = $null }, @{ Value = 'diagnostic-secret-container' },
        @{ Value = [pscustomobject]@{ Code = 'InvalidResponse'; Predicate = 'ResponseStatus' } },
        @{ Value = @(@{ Code = 'InvalidResponse'; Predicate = 'ResponseStatus' }) }
    ) {
        Assert-ProbeTestFailure Unknown UnexpectedFailure 0 UnexpectedFailure -Action {
            $phase = 'DiscoveryResponse'; $diagnostic = $Value
            & $script:probeFailureEmission
        }
    }

    It 'emits exactly the independently frozen permitted tuple: <Phase>/<Code>/<Predicate>' -ForEach $probeExpectedTuples {
        Assert-ProbeTestFailure $Phase $Code 0 $Predicate -Action {
            $phase = $Phase; $diagnostic = @{ Code = $Code; Predicate = $Predicate }
            & $script:probeFailureEmission
        }
    }
    It 'normalizes the complete tuple when any label is invalid or belongs to another tuple: <Case>' -ForEach @(
        @{ Case = 'both unknown'; InputPhase = 'diagnostic-secret-phase'; InputCode = 'diagnostic-secret-code'; InputPredicate = 'diagnostic-secret-predicate' },
        @{ Case = 'unknown phase'; InputPhase = 'diagnostic-secret-phase'; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'unknown code'; InputPhase = 'DiscoveryResponse'; InputCode = 'diagnostic-secret-code'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'unknown predicate'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = 'diagnostic-secret-predicate' },
        @{ Case = 'wrong phase case'; InputPhase = 'discoveryresponse'; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'wrong code case'; InputPhase = 'DiscoveryResponse'; InputCode = 'invalidresponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'wrong predicate case'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = 'responsestatus' },
        @{ Case = 'missing labels'; InputPhase = $null; InputCode = $null; InputPredicate = $null },
        @{ Case = 'missing phase'; InputPhase = $null; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'missing code'; InputPhase = 'DiscoveryResponse'; InputCode = $null; InputPredicate = 'ResponseStatus' },
        @{ Case = 'missing predicate'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = $null },
        @{ Case = 'phase single array'; InputPhase = @('DiscoveryResponse'); InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'code single array'; InputPhase = 'DiscoveryResponse'; InputCode = @('InvalidResponse'); InputPredicate = 'ResponseStatus' },
        @{ Case = 'predicate single array'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = @('ResponseStatus') },
        @{ Case = 'multiple labels'; InputPhase = @('DiscoveryResponse', 'diagnostic-secret'); InputCode = @('InvalidResponse', 'diagnostic-secret'); InputPredicate = @('ResponseStatus', 'diagnostic-secret') },
        @{ Case = 'phase object'; InputPhase = [pscustomobject]@{ Value = 'DiscoveryResponse' }; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'code object'; InputPhase = 'DiscoveryResponse'; InputCode = [pscustomobject]@{ Value = 'InvalidResponse' }; InputPredicate = 'ResponseStatus' },
        @{ Case = 'predicate object'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = [pscustomobject]@{ Value = 'ResponseStatus' } },
        @{ Case = 'number phase'; InputPhase = 1; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'boolean code'; InputPhase = 'DiscoveryResponse'; InputCode = $true; InputPredicate = 'ResponseStatus' },
        @{ Case = 'dictionary predicate'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = @{ ResponseStatus = $true } },
        @{ Case = 'newline predicate'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = "ResponseStatus`ndiagnostic-secret" },
        @{ Case = 'valid labels wrong phase'; InputPhase = 'TokenBinding'; InputCode = 'InvalidResponse'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'valid labels wrong code'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidConfiguration'; InputPredicate = 'ResponseStatus' },
        @{ Case = 'valid labels wrong predicate'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = 'CallbackScheme' },
        @{ Case = 'request invocation wrong category'; InputPhase = 'DiscoveryRequest'; InputCode = 'TransportFailure'; InputPredicate = 'RequestInvocation' },
        @{ Case = 'transport label wrong category'; InputPhase = 'DiscoveryRequest'; InputCode = 'UnexpectedFailure'; InputPredicate = 'TransportSend' },
        @{ Case = 'fallback predicate with rejection category'; InputPhase = 'DiscoveryResponse'; InputCode = 'InvalidResponse'; InputPredicate = 'UnexpectedFailure' }
    ) {
        Assert-ProbeTestFailure Unknown UnexpectedFailure 0 UnexpectedFailure -Action {
            $phase = $InputPhase; $diagnostic = @{ Code = $InputCode; Predicate = $InputPredicate }
            & $script:probeFailureEmission
        }
    }

}

Describe 'Native transport is inspected but never executed' {
    # These source contracts do not establish real HttpClient timeout, TLS,
    # streaming-limit or redirect behavior. A separate fake HttpMessageHandler
    # injection seam would be needed to exercise those behaviors without HTTP.
    It 'has only one explicit, fully replaced HTTP boundary' {
        (Get-Command Send-LabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Match 'Native HTTP is unavailable'
        (Get-Command Send-LabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Not -Match 'HttpClient|SendAsync'
        (Get-Command Send-BaselineLabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Match 'Native HTTP is unavailable'
        (Get-Command Send-BaselineLabProbeRequest -CommandType Function).ScriptBlock.ToString() | Should -Not -Match 'HttpClient|SendAsync'
        Get-Command New-BaselineLabProbeHttpHandler -CommandType Function -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'forbids automatic redirects, ambient cookies, credentials and proxies in native source' {
        foreach ($setting in @('AllowAutoRedirect', 'UseCookies', 'UseDefaultCredentials', 'UseProxy')) {
            $script:probeTransportSource | Should -Match ('\.' + $setting + '\s*=\s*\$false')
            $script:probeTransportSource | Should -Not -Match ('\.' + $setting + '\s*=\s*\$true')
        }
        $script:probeTransportSource | Should -Not -Match 'ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificateValidator|DefaultNetworkCredentials|CredentialCache|CookieContainer'
    }
    It 'pins HTTPS destinations and bounds response time and size without fetching metadata or JWKS elsewhere' {
        $script:probeTransportSource | Should -Match "Scheme\s+-cne\s+'https'"
        $script:probeTransportSource | Should -Match 'Port\s+-ne\s+443'
        $script:probeTransportSource | Should -Match 'login\.microsoftonline\.com'
        $script:probeTransportSource | Should -Match 'graph\.microsoft\.com'
        $script:probeTransportSource | Should -Match '\.UserInfo'
        $script:probeTransportSource | Should -Match '\.Fragment'
        $script:probeTransportSource | Should -Match 'FromSeconds\(30\)'
        $script:probeTransportSource | Should -Match '65536'
        $script:probeTransportSource | Should -Match 'CancellationTokenSource'
        $script:probeTransportSource | Should -Match 'sensitive response suppressed'
    }
    It 'does not accept caller-supplied tokens or expose a general token-refresh interface' {
        $names = (Get-Command Invoke-LabSessionProbe).Parameters.Keys
        foreach ($forbidden in @('IdToken', 'AccessToken', 'RefreshToken', 'ClientSecret', 'Credential')) {
            $names | Should -Not -Contain $forbidden
        }
        $script:probeSource | Should -Not -Match 'grant_type\s*=\s*[''"]refresh_token|scope\s*=\s*[''"][^''"]*offline_access'
        $script:probeSource | Should -Match 'OIDC Core 3\.1\.3\.7 step 6'
        $script:probeSource | Should -Match 'TamperProofAgainstCandidate\s*=\s*\$false'
    }
}

Describe 'Static diagnostic operation and guard contracts' {
    It 'pins the exact RFC 6749 scope syntax instead of a returned-name allowlist' {
        $invoke = @($script:probeDefinitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0].Extent.Text
        $invoke | Should -Match ([regex]::Escape('$tokens.scope -cnotmatch ''\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z'''))
        $invoke | Should -Not -Match 'ScopeAllowedGrammar'
    }
    It 'preserves the exact baseline form serializer source independently of normalized traces' {
        $baseline = @($script:probeBaselineDefinitions | Where-Object Name -CEQ 'ConvertTo-LabProbeForm')
        $candidate = @($script:probeDefinitions | Where-Object Name -CEQ 'ConvertTo-LabProbeForm')
        $baseline.Count | Should -Be 1
        $candidate.Count | Should -Be 1
        $candidate[0].Extent.Text | Should -BeExactly $baseline[0].Extent.Text
    }
    It 'preserves the exact original request-form expression for <Variable>' -ForEach @(@{ Variable = '$query' }, @{ Variable = '$body' }) {
        $baselineInvoke = @($script:probeBaselineDefinitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0]
        $candidateInvoke = @($script:probeDefinitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0]
        $findExpression = {
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -ceq $Variable -and
                $node.Right.Extent.Text.StartsWith('ConvertTo-LabProbeForm ', [StringComparison]::Ordinal)
        }
        $baseline = @($baselineInvoke.FindAll($findExpression, $true))
        $candidate = @($candidateInvoke.FindAll($findExpression, $true))
        $baseline.Count | Should -Be 1
        $candidate.Count | Should -Be 1
        $candidate[0].Extent.Text | Should -BeExactly $baseline[0].Extent.Text
    }
    It 'has no missing or extra public tuple relative to the independent frozen vocabulary' -ForEach @(@{ Expected = $probeExpectedTuples }) {
        $expectedTuples = @($Expected | Where-Object Phase -CNE 'Unknown' | ForEach-Object { $_.Phase + '/' + $_.Code + '/' + $_.Predicate } | Sort-Object -CaseSensitive)
        $allowlist = Get-LabProbeDiagnosticAllowlist
        $actualTuples = @(foreach ($key in $allowlist.Keys) { foreach ($predicate in $allowlist[$key]) { $key + '/' + $predicate } }) | Sort-Object -CaseSensitive
        ($actualTuples -join "`n") | Should -BeExactly ($expectedTuples -join "`n")
        @($actualTuples | Select-Object -Unique).Count | Should -Be $actualTuples.Count
    }
    It 'keeps static operation markers adjacent to their entered operations: <Function> <Marker>' -ForEach @(
        @{ Function = 'Read-LabProbeJson'; Marker = '$Diagnostic.Predicate = $ids[0]'; Operation = '$document = [System.Text.Json.JsonDocument]::Parse($Text)' },
        @{ Function = 'Read-LabProbeJson'; Marker = '$Diagnostic.Predicate = $ids[2]'; Operation = '$names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)' },
        @{ Function = 'Read-LabProbeJson'; Marker = '$Diagnostic.Predicate = $ids[3]'; Operation = 'foreach ($property in $document.RootElement.EnumerateObject())' },
        @{ Function = 'Read-LabProbeJson'; Marker = '$Diagnostic.Predicate = $ids[5]'; Operation = 'return ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 16 -ErrorAction Stop' },
        @{ Function = 'Read-LabProbeJson'; Marker = '$Diagnostic.Predicate = $ids[6]'; Operation = '$document.Dispose()' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'ConfigurationValidation'"; Operation = 'Assert-LabProbeConfiguration $TenantId $ClientId $ExpectedUpn -Diagnostic $diagnostic' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'StateCreation'"; Operation = '$state = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'NonceCreation'"; Operation = '$nonce = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'VerifierCreation'"; Operation = '$verifier = ConvertTo-LabProbeBase64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'ChallengeCreation'"; Operation = '$challenge = ConvertTo-LabProbeBase64Url ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'AuthorizationFormCreation'"; Operation = '$query = ConvertTo-LabProbeForm' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'AuthorizationUriConstruction'"; Operation = '$current = "$($metadata.authorization_endpoint)?$query"' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'CallbackUriConstruction'"; Operation = '$next = [uri]::new([uri]$current, [string]$response.Locations[0])' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'CallbackQueryParsing'"; Operation = '$fields = [Web.HttpUtility]::ParseQueryString($next.Query)' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'TokenFormCreation'"; Operation = '$body = ConvertTo-LabProbeForm' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'TokenSplit'"; Operation = '$parts = $tokens.id_token.Split(''.'')' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = '$diagnostic.Predicate = $partIds[5]'; Operation = '$decoder = [Text.UTF8Encoding]::new($false, $true)' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = '$diagnostic.Predicate = $partIds[2]'; Operation = '$encoded = [Convert]::FromBase64String($encoded)' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = '$diagnostic.Predicate = $partIds[3]'; Operation = '$encoded = $decoder.GetString($encoded)' },
        @{ Function = 'Invoke-LabSessionProbe'; Marker = "Predicate = 'ClockRead'"; Operation = '$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()' }
    ) {
        # This proves source placement, not native constructor/disposal failure
        # semantics. Native transport remains excluded from execution here.
        $source = @($script:probeDefinitions | Where-Object Name -CEQ $Function)[0].Extent.Text
        $markerOffset = $source.IndexOf($Marker, [StringComparison]::Ordinal)
        $markerOffset | Should -BeGreaterOrEqual 0
        $operationOffset = $source.IndexOf($Operation, $markerOffset, [StringComparison]::Ordinal)
        $operationOffset | Should -BeGreaterThan $markerOffset
        $between = $source.Substring($markerOffset + $Marker.Length, $operationOffset - $markerOffset - $Marker.Length)
        $between | Should -Not -Match '\.Predicate\s*='
    }
    It 'marks exactly the four request invocations without changing their arguments' {
        $source = @($script:probeDefinitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0].Extent.Text
        ([regex]::Matches($source, "Predicate = 'RequestInvocation'")).Count | Should -Be 4
        foreach ($operation in @(
            '$metadata = Send-LabProbeRequest "$authority/v2.0/.well-known/openid-configuration" -Diagnostic $diagnostic',
            '$response = Send-LabProbeRequest $current -Headers @{ Cookie = "$CookieName=$Cookie" } -Diagnostic $diagnostic',
            '$tokens = Send-LabProbeRequest $metadata.token_endpoint -Method POST -Body $body -Diagnostic $diagnostic',
            '$user = Send-LabProbeRequest $metadata.userinfo_endpoint -Headers @{ Authorization = "Bearer $($tokens.access_token)" } -Diagnostic $diagnostic'
        )) {
            $offset = $source.IndexOf($operation, [StringComparison]::Ordinal)
            $offset | Should -BeGreaterThan 0
            $prefix = $source.Substring(0, $offset)
            $prefix | Should -Match "Predicate = 'RequestInvocation'\s*$"
        }
    }
    It 'pins the fixed JSON context and token-part operation mappings in original order' {
        $json = @($script:probeDefinitions | Where-Object Name -CEQ 'Read-LabProbeJson')[0].Extent.Text
        foreach ($context in @('Response', 'Header', 'Claims')) {
            $markers = @('JsonParse', 'JsonRootObject', 'JsonPropertySetConstruction', 'JsonPropertiesRead', 'JsonPropertyUnique', 'JsonConversion', 'JsonDispose')
            $last = -1
            foreach ($marker in $markers) {
                $offset = $json.IndexOf("'$context$marker'", [StringComparison]::Ordinal)
                $offset | Should -BeGreaterThan $last
                $last = $offset
            }
        }
        $invoke = @($script:probeDefinitions | Where-Object Name -CEQ 'Invoke-LabSessionProbe')[0].Extent.Text
        $invoke | Should -Match ([regex]::Escape("@('HeaderAlphabet', 'HeaderLength', 'HeaderBase64Decode', 'HeaderUtf8Decode', 'Header', 'HeaderUtf8Construction')"))
        $invoke | Should -Match ([regex]::Escape("@('ClaimsAlphabet', 'ClaimsLength', 'ClaimsBase64Decode', 'ClaimsUtf8Decode', 'Claims', 'ClaimsUtf8Construction')"))
        $invoke | Should -Match 'Read-LabProbeJson\s+\$encoded\s+-Diagnostic\s+\$diagnostic\s+-Context\s+\$partIds\[4\]'
    }
    It 'assigns rejection labels inside true branches instead of while evaluating their guard' {
        foreach ($name in @('Assert-LabProbeConfiguration', 'Read-LabProbeResponse', 'Read-LabProbeJson', 'Invoke-LabSessionProbe')) {
            $definition = @($script:probeDefinitions | Where-Object Name -CEQ $name)[0]
            $guards = $definition.FindAll({ param($node) $node -is [Management.Automation.Language.IfStatementAst] }, $true)
            foreach ($guard in $guards) {
                foreach ($clause in $guard.Clauses) {
                    $body = $clause.Item2.Extent.Text
                    if (@($clause.Item2.Statements | Where-Object { $_ -is [Management.Automation.Language.ThrowStatementAst] }).Count -eq 0) { continue }
                    $siblings = @($guard.Parent.Statements)
                    $position = [Array]::IndexOf([object[]]$siblings, $guard)
                    $position | Should -BeGreaterThan 0
                    $siblings[$position - 1].Extent.Text | Should -Match '\.Predicate\s*=\s*''UnexpectedFailure'''
                    $clause.Item1.Extent.Text | Should -Not -Match '\.Predicate\s*='
                    # Each actual throw branch sets a category and predicate before
                    # the throw; no external field is used as a literal label.
                    $body | Should -Match '(?s)\.Code\s*=.*\.Predicate\s*=.*\bthrow\b'
                }
            }
        }
    }
}
