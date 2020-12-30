import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class GlwdOIDCParams extends Component {
  constructor(props) {
    super(props);

    props.mod.parameters?"":(props.mod.parameters = {});
    props.mod.parameters["jwt-type"]?"":(props.mod.parameters["jwt-type"] = "rsa");
    props.mod.parameters["jwt-key-size"]!==undefined?"":(props.mod.parameters["jwt-key-size"] = "256");
    props.mod.parameters["jwks-uri"]?"":(props.mod.parameters["jwks-uri"] = "");
    props.mod.parameters["jwks-private"]?"":(props.mod.parameters["jwks-private"] = "");
    props.mod.parameters["default-kid"]?"":(props.mod.parameters["default-kid"] = "");
    props.mod.parameters["client-sign_kid-parameter"]?"":(props.mod.parameters["client-sign_kid-parameter"] = "");
    props.mod.parameters["jwks-public"]?"":(props.mod.parameters["jwks-public"] = "");
    props.mod.parameters["key"]?"":(props.mod.parameters["key"] = "");
    props.mod.parameters["cert"]?"":(props.mod.parameters["cert"] = "");
    props.mod.parameters["access-token-duration"]!==undefined?"":(props.mod.parameters["access-token-duration"] = 3600);
    props.mod.parameters["refresh-token-duration"]!==undefined?"":(props.mod.parameters["refresh-token-duration"] = 1209600);
    props.mod.parameters["code-duration"]!==undefined?"":(props.mod.parameters["code-duration"] = 600);
    props.mod.parameters["refresh-token-rolling"]!==undefined?"":(props.mod.parameters["refresh-token-rolling"] = true);
    props.mod.parameters["refresh-token-one-use"]!==undefined?"":(props.mod.parameters["refresh-token-one-use"] = "never");
    props.mod.parameters["client-refresh-token-one-use-parameter"]!==undefined?"":(props.mod.parameters["client-refresh-token-one-use-parameter"] = "refresh-token-one-use");
    props.mod.parameters["allow-non-oidc"]!==undefined?"":(props.mod.parameters["allow-non-oidc"] = false);
    props.mod.parameters["auth-type-code-enabled"]!==undefined?"":(props.mod.parameters["auth-type-code-enabled"] = true);
    props.mod.parameters["auth-type-code-revoke-replayed"]!==undefined?"":(props.mod.parameters["auth-type-code-revoke-replayed"] = false);
    props.mod.parameters["auth-type-token-enabled"]!==undefined?"":(props.mod.parameters["auth-type-token-enabled"] = true);
    props.mod.parameters["auth-type-id-token-enabled"] = true;
    props.mod.parameters["auth-type-none-enabled"]!==undefined?"":(props.mod.parameters["auth-type-none-enabled"] = true);
    props.mod.parameters["auth-type-password-enabled"]!==undefined?"":(props.mod.parameters["auth-type-password-enabled"] = false);
    props.mod.parameters["auth-type-client-enabled"]!==undefined?"":(props.mod.parameters["auth-type-client-enabled"] = true);
    props.mod.parameters["auth-type-device-enabled"]!==undefined?"":(props.mod.parameters["auth-type-device-enabled"] = false);
    props.mod.parameters["auth-type-refresh-enabled"]!==undefined?"":(props.mod.parameters["auth-type-refresh-enabled"] = true);
    props.mod.parameters["scope"]?"":(props.mod.parameters["scope"] = []);
    props.mod.parameters["additional-parameters"]?"":(props.mod.parameters["additional-parameters"] = []);
    props.mod.parameters["claims"]?"":(props.mod.parameters["claims"] = []);
    props.mod.parameters["service-documentation"]!==undefined?"":(props.mod.parameters["service-documentation"] = "https://github.com/babelouest/glewlwyd/tree/master/docs");
    props.mod.parameters["op-policy-uri"]!==undefined?"":(props.mod.parameters["op-policy-uri"] = "");
    props.mod.parameters["op-tos-uri"]!==undefined?"":(props.mod.parameters["op-tos-uri"] = "");
    props.mod.parameters["jwks-show"]!==undefined?"":(props.mod.parameters["jwks-show"] = true);
    props.mod.parameters["jwks-x5c"]!==undefined?"":(props.mod.parameters["jwks-x5c"] = []);
    props.mod.parameters["request-parameter-allow"]!==undefined?"":(props.mod.parameters["request-parameter-allow"] = true);
    props.mod.parameters["request-uri-allow-https-non-secure"]!==undefined?"":(props.mod.parameters["request-uri-allow-https-non-secure"] = false);
    props.mod.parameters["secret-type"]?"":(props.mod.parameters["secret-type"] = "pairwise");
    props.mod.parameters["address-claim"]?"":(props.mod.parameters["address-claim"] = {type: "no", formatted: "", street_address: "", locality: "", region: "", postal_code: "", country: "", mandatory: false});
    props.mod.parameters["name-claim"]?"":(props.mod.parameters["name-claim"] = "on-demand");
    props.mod.parameters["name-claim-scope"]?"":(props.mod.parameters["name-claim-scope"] = []);
    props.mod.parameters["email-claim"]?"":(props.mod.parameters["email-claim"] = "no");
    props.mod.parameters["email-claim-scope"]?"":(props.mod.parameters["email-claim-scope"] = []);
    props.mod.parameters["scope-claim"]?"":(props.mod.parameters["scope-claim"] = "no");
    props.mod.parameters["scope-claim-scope"]?"":(props.mod.parameters["scope-claim-scope"] = []);
    props.mod.parameters["allowed-scope"]?"":(props.mod.parameters["allowed-scope"] = ["openid"]);
    props.mod.parameters["pkce-allowed"]!==undefined?"":(props.mod.parameters["pkce-allowed"] = false);
    props.mod.parameters["pkce-method-plain-allowed"]!==undefined?"":(props.mod.parameters["pkce-method-plain-allowed"] = false);
    props.mod.parameters["introspection-revocation-allowed"]!==undefined?"":(props.mod.parameters["introspection-revocation-allowed"] = false);
    props.mod.parameters["introspection-revocation-auth-scope"]!==undefined?"":(props.mod.parameters["introspection-revocation-auth-scope"] = []);
    props.mod.parameters["introspection-revocation-allow-target-client"]!==undefined?"":(props.mod.parameters["introspection-revocation-allow-target-client"] = true);
    props.mod.parameters["register-client-allowed"]!==undefined?"":(props.mod.parameters["register-client-allowed"] = false);
    props.mod.parameters["register-client-auth-scope"]!==undefined?"":(props.mod.parameters["register-client-auth-scope"] = []);
    props.mod.parameters["register-client-credentials-scope"]!==undefined?"":(props.mod.parameters["register-client-credentials-scope"] = []);
    props.mod.parameters["register-client-management-allowed"]!==undefined?"":(props.mod.parameters["register-client-management-allowed"] = true);
    props.mod.parameters["register-resource-specify-allowed"]!==undefined?"":(props.mod.parameters["register-resource-specify-allowed"] = false);
    props.mod.parameters["register-resource-default"]!==undefined?"":(props.mod.parameters["register-resource-default"] = []);
    props.mod.parameters["session-management-allowed"]!==undefined?"":(props.mod.parameters["session-management-allowed"] = false);
    props.mod.parameters["client-pubkey-parameter"]!==undefined?"":(props.mod.parameters["client-pubkey-parameter"] = "");
    props.mod.parameters["client-jwks-parameter"]!==undefined?"":(props.mod.parameters["client-jwks-parameter"] = "jwks");
    props.mod.parameters["client-jwks_uri-parameter"]!==undefined?"":(props.mod.parameters["client-jwks_uri-parameter"] = "jwks_uri");
    props.mod.parameters["request-maximum-exp"]!==undefined?"":(props.mod.parameters["request-maximum-exp"] = 3600);
    props.mod.parameters["encrypt-out-token-allow"]!==undefined?"":(props.mod.parameters["encrypt-out-token-allow"] = false);
    props.mod.parameters["client-enc-parameter"]!==undefined?"":(props.mod.parameters["client-enc-parameter"] = "enc");
    props.mod.parameters["client-alg-parameter"]!==undefined?"":(props.mod.parameters["client-alg-parameter"] = "alg");
    props.mod.parameters["client-alg_kid-parameter"]!==undefined?"":(props.mod.parameters["client-alg_kid-parameter"] = "alg_kid");
    props.mod.parameters["client-encrypt_code-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_code-parameter"] = "encrypt_code");
    props.mod.parameters["client-encrypt_at-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_at-parameter"] = "encrypt_at");
    props.mod.parameters["client-encrypt_userinfo-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_userinfo-parameter"] = "encrypt_userinfo");
    props.mod.parameters["client-encrypt_id_token-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_id_token-parameter"] = "encrypt_id_token");
    props.mod.parameters["client-encrypt_refresh_token-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_refresh_token-parameter"] = "encrypt_refresh_token");
    props.mod.parameters["client-encrypt_introspection-parameter"]!==undefined?"":(props.mod.parameters["client-encrypt_introspection-parameter"] = "encrypt_introspection");
    props.mod.parameters["device-authorization-expiration"]!==undefined?"":(props.mod.parameters["device-authorization-expiration"] = 600);
    props.mod.parameters["device-authorization-interval"]!==undefined?"":(props.mod.parameters["device-authorization-interval"] = 5);
    props.mod.parameters["client-cert-header-name"]!==undefined?"":(props.mod.parameters["client-cert-header-name"] = "SSL_CLIENT_CERT");
    props.mod.parameters["client-cert-use-endpoint-aliases"]!==undefined?"":(props.mod.parameters["client-cert-use-endpoint-aliases"] = false);
    props.mod.parameters["client-cert-self-signed-allowed"]!==undefined?"":(props.mod.parameters["client-cert-self-signed-allowed"] = false);
    props.mod.parameters["oauth-dpop-allowed"]!==undefined?"":(props.mod.parameters["oauth-dpop-allowed"] = false);
    props.mod.parameters["oauth-dpop-iat-duration"]!==undefined?"":(props.mod.parameters["oauth-dpop-iat-duration"] = 10);
    props.mod.parameters["resource-allowed"]!==undefined?"":(props.mod.parameters["resource-allowed"] = false);
    props.mod.parameters["resource-scope"]!==undefined?"":(props.mod.parameters["resource-scope"] = {});
    props.mod.parameters["resource-client-property"]!==undefined?"":(props.mod.parameters["resource-client-property"] = "");
    props.mod.parameters["resource-scope-and-client-property"]!==undefined?"":(props.mod.parameters["resource-scope-and-client-property"] = false);
    props.mod.parameters["resource-change-allowed"]!==undefined?"":(props.mod.parameters["resource-change-allowed"] = false);
    props.mod.parameters["oauth-rar-allowed"]!==undefined?"":(props.mod.parameters["oauth-rar-allowed"] = false);
    props.mod.parameters["rar-types-client-property"]!==undefined?"":(props.mod.parameters["rar-types-client-property"] = "authorization_data_types");
    props.mod.parameters["rar-allow-auth-unsigned"]!==undefined?"":(props.mod.parameters["rar-allow-auth-unsigned"] = false);
    props.mod.parameters["rar-allow-auth-unencrypted"]!==undefined?"":(props.mod.parameters["rar-allow-auth-unencrypted"] = true);
    props.mod.parameters["rar-types"]!==undefined?"":(props.mod.parameters["rar-types"] = {});

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      errorList: {},
      newScopeOverride: false,
      newResourceScope: false,
      newRar: "",
      newRarExists: false,
      newRarInvalidChar: false
    };

    if (this.state.check) {
      this.checkParameters();
    }

    this.checkParameters = this.checkParameters.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.changeParamWithValue = this.changeParamWithValue.bind(this);
    this.changeNumberParam = this.changeNumberParam.bind(this);
    this.emptyParameter = this.emptyParameter.bind(this);
    this.toggleParam = this.toggleParam.bind(this);
    this.changeJwtType = this.changeJwtType.bind(this);
    this.changeSecretType = this.changeSecretType.bind(this);
    this.setNewScopeOverride = this.setNewScopeOverride.bind(this);
    this.addScopeOverride = this.addScopeOverride.bind(this);
    this.changeScopeOverrideRefreshDuration = this.changeScopeOverrideRefreshDuration.bind(this);
    this.toggleScopeOverrideRolling = this.toggleScopeOverrideRolling.bind(this);
    this.addAdditionalParameter = this.addAdditionalParameter.bind(this);
    this.setAdditionalPropertyUserParameter = this.setAdditionalPropertyUserParameter.bind(this);
    this.setAdditionalPropertyTokenParameter = this.setAdditionalPropertyTokenParameter.bind(this);
    this.deleteAdditionalProperty = this.deleteAdditionalProperty.bind(this);
    this.addClaim = this.addClaim.bind(this);
    this.deleteClaim = this.deleteClaim.bind(this);
    this.setClaimName = this.setClaimName.bind(this);
    this.setClaimUserProperty = this.setClaimUserProperty.bind(this);
    this.setClaimType = this.setClaimType.bind(this);
    this.setClaimBooleanTrue = this.setClaimBooleanTrue.bind(this);
    this.setClaimBooleanFalse = this.setClaimBooleanFalse.bind(this);
    this.toggleClaimMandatory = this.toggleClaimMandatory.bind(this);
    this.toggleClaimOnDemand = this.toggleClaimOnDemand.bind(this);
    this.uploadFile = this.uploadFile.bind(this);
    this.uploadX5cFile = this.uploadX5cFile.bind(this);
    this.handleRemoveX5c = this.handleRemoveX5c.bind(this);
    this.changeAddressClaimParam = this.changeAddressClaimParam.bind(this);
    this.changeAddressClaim = this.changeAddressClaim.bind(this);
    this.toggleAddrClaimMandatory = this.toggleAddrClaimMandatory.bind(this);
    this.addScopeClaim = this.addScopeClaim.bind(this);
    this.deleteScopeClaim = this.deleteScopeClaim.bind(this);
    this.addNameScope = this.addNameScope.bind(this);
    this.deleteNameScope = this.deleteNameScope.bind(this);
    this.addEmailScope = this.addEmailScope.bind(this);
    this.deleteEmailScope = this.deleteEmailScope.bind(this);
    this.addAllowedScope = this.addAllowedScope.bind(this);
    this.deleteAllowedScope = this.deleteAllowedScope.bind(this);
    this.addScope = this.addScope.bind(this);
    this.deleteScope = this.deleteScope.bind(this);
    this.setResourceScope = this.setResourceScope.bind(this);
    this.addResourceScope = this.addResourceScope.bind(this);
    this.changeResourceScopeUrls = this.changeResourceScopeUrls.bind(this);
    this.addRAR = this.addRAR.bind(this);
  }

  componentWillReceiveProps(nextProps) {

    nextProps.mod.parameters?"":(nextProps.mod.parameters = {});
    nextProps.mod.parameters["jwt-type"]?"":(nextProps.mod.parameters["jwt-type"] = "rsa");
    nextProps.mod.parameters["jwt-key-size"]!==undefined?"":(nextProps.mod.parameters["jwt-key-size"] = "256");
    nextProps.mod.parameters["jwks-uri"]?"":(nextProps.mod.parameters["jwks-uri"] = "");
    nextProps.mod.parameters["jwks-private"]?"":(nextProps.mod.parameters["jwks-private"] = "");
    nextProps.mod.parameters["default-kid"]?"":(nextProps.mod.parameters["default-kid"] = "");
    nextProps.mod.parameters["client-sign_kid-parameter"]?"":(nextProps.mod.parameters["client-sign_kid-parameter"] = "");
    nextProps.mod.parameters["jwks-public-uri"]?"":(nextProps.mod.parameters["jwks-public-uri"] = "");
    nextProps.mod.parameters["jwks-public"]?"":(nextProps.mod.parameters["jwks-public"] = "");
    nextProps.mod.parameters["key"]?"":(nextProps.mod.parameters["key"] = "");
    nextProps.mod.parameters["cert"]?"":(nextProps.mod.parameters["cert"] = "");
    nextProps.mod.parameters["access-token-duration"]!==undefined?"":(nextProps.mod.parameters["access-token-duration"] = 3600);
    nextProps.mod.parameters["refresh-token-duration"]!==undefined?"":(nextProps.mod.parameters["refresh-token-duration"] = 1209600);
    nextProps.mod.parameters["code-duration"]!==undefined?"":(nextProps.mod.parameters["code-duration"] = 600);
    nextProps.mod.parameters["refresh-token-rolling"]!==undefined?"":(nextProps.mod.parameters["refresh-token-rolling"] = true);
    nextProps.mod.parameters["refresh-token-one-use"]!==undefined?"":(nextProps.mod.parameters["refresh-token-one-use"] = "never");
    nextProps.mod.parameters["client-refresh-token-one-use-parameter"]!==undefined?"":(nextProps.mod.parameters["client-refresh-token-one-use-parameter"] = "refresh-token-one-use");
    nextProps.mod.parameters["allow-non-oidc"]!==undefined?"":(nextProps.mod.parameters["allow-non-oidc"] = false);
    nextProps.mod.parameters["auth-type-code-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-code-enabled"] = true);
    nextProps.mod.parameters["auth-type-code-revoke-replayed"]!==undefined?"":(nextProps.mod.parameters["auth-type-code-revoke-replayed"] = false);
    nextProps.mod.parameters["auth-type-token-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-token-enabled"] = true);
    nextProps.mod.parameters["auth-type-id-token-enabled"] = true;
    nextProps.mod.parameters["auth-type-none-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-none-enabled"] = true);
    nextProps.mod.parameters["auth-type-password-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-password-enabled"] = false);
    nextProps.mod.parameters["auth-type-client-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-client-enabled"] = true);
    nextProps.mod.parameters["auth-type-device-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-device-enabled"] = false);
    nextProps.mod.parameters["auth-type-refresh-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-refresh-enabled"] = true);
    nextProps.mod.parameters["scope"]?"":(nextProps.mod.parameters["scope"] = []);
    nextProps.mod.parameters["additional-parameters"]?"":(nextProps.mod.parameters["additional-parameters"] = []);
    nextProps.mod.parameters["claims"]?"":(nextProps.mod.parameters["claims"] = []);
    nextProps.mod.parameters["service-documentation"]!==undefined?"":(nextProps.mod.parameters["service-documentation"] = "https://github.com/babelouest/glewlwyd/tree/master/docs");
    nextProps.mod.parameters["op-policy-uri"]!==undefined?"":(nextProps.mod.parameters["op-policy-uri"] = "");
    nextProps.mod.parameters["op-tos-uri"]!==undefined?"":(nextProps.mod.parameters["op-tos-uri"] = "");
    nextProps.mod.parameters["jwks-show"]!==undefined?"":(nextProps.mod.parameters["jwks-show"] = true);
    nextProps.mod.parameters["jwks-x5c"]!==undefined?"":(nextProps.mod.parameters["jwks-x5c"] = []);
    nextProps.mod.parameters["request-parameter-allow"]!==undefined?"":(nextProps.mod.parameters["request-parameter-allow"] = true);
    nextProps.mod.parameters["request-uri-allow-https-non-secure"]!==undefined?"":(nextProps.mod.parameters["request-uri-allow-https-non-secure"] = false);
    nextProps.mod.parameters["secret-type"]?"":(nextProps.mod.parameters["secret-type"] = "pairwise");
    nextProps.mod.parameters["address-claim"]?"":(nextProps.mod.parameters["address-claim"] = {type: "no", formatted: "", street_address: "", locality: "", region: "", postal_code: "", country: "", mandatory: false});
    nextProps.mod.parameters["name-claim"]?"":(nextProps.mod.parameters["name-claim"] = "on-demand");
    nextProps.mod.parameters["name-claim-scope"]?"":(nextProps.mod.parameters["name-claim-scope"] = []);
    nextProps.mod.parameters["email-claim"]?"":(nextProps.mod.parameters["email-claim"] = "no");
    nextProps.mod.parameters["email-claim-scope"]?"":(nextProps.mod.parameters["email-claim-scope"] = []);
    nextProps.mod.parameters["scope-claim"]?"":(nextProps.mod.parameters["scope-claim"] = "no");
    nextProps.mod.parameters["scope-claim-scope"]?"":(nextProps.mod.parameters["scope-claim-scope"] = []);
    nextProps.mod.parameters["allowed-scope"]?"":(nextProps.mod.parameters["allowed-scope"] = ["openid"]);
    nextProps.mod.parameters["pkce-allowed"]!==undefined?"":(nextProps.mod.parameters["pkce-allowed"] = false);
    nextProps.mod.parameters["pkce-method-plain-allowed"]!==undefined?"":(nextProps.mod.parameters["pkce-method-plain-allowed"] = false);
    nextProps.mod.parameters["introspection-revocation-allowed"]!==undefined?"":(nextProps.mod.parameters["introspection-revocation-allowed"] = false);
    nextProps.mod.parameters["introspection-revocation-auth-scope"]!==undefined?"":(nextProps.mod.parameters["introspection-revocation-auth-scope"] = []);
    nextProps.mod.parameters["introspection-revocation-allow-target-client"]!==undefined?"":(nextProps.mod.parameters["introspection-revocation-allow-target-client"] = true);
    nextProps.mod.parameters["register-client-allowed"]!==undefined?"":(nextProps.mod.parameters["register-client-allowed"] = false);
    nextProps.mod.parameters["register-client-auth-scope"]!==undefined?"":(nextProps.mod.parameters["register-client-auth-scope"] = []);
    nextProps.mod.parameters["register-client-credentials-scope"]!==undefined?"":(nextProps.mod.parameters["register-client-credentials-scope"] = []);
    nextProps.mod.parameters["register-client-management-allowed"]!==undefined?"":(nextProps.mod.parameters["register-client-management-allowed"] = true);
    nextProps.mod.parameters["register-resource-specify-allowed"]!==undefined?"":(nextProps.mod.parameters["register-resource-specify-allowed"] = false);
    nextProps.mod.parameters["register-resource-default"]!==undefined?"":(nextProps.mod.parameters["register-resource-default"] = []);
    nextProps.mod.parameters["session-management-allowed"]!==undefined?"":(nextProps.mod.parameters["session-management-allowed"] = false);
    nextProps.mod.parameters["client-pubkey-parameter"]!==undefined?"":(nextProps.mod.parameters["client-pubkey-parameter"] = "");
    nextProps.mod.parameters["client-jwks-parameter"]!==undefined?"":(nextProps.mod.parameters["client-jwks-parameter"] = "jwks");
    nextProps.mod.parameters["client-jwks_uri-parameter"]!==undefined?"":(nextProps.mod.parameters["client-jwks_uri-parameter"] = "jwks_uri");
    nextProps.mod.parameters["request-maximum-exp"]!==undefined?"":(nextProps.mod.parameters["request-maximum-exp"] = 3600);
    nextProps.mod.parameters["encrypt-out-token-allow"]!==undefined?"":(nextProps.mod.parameters["encrypt-out-token-allow"] = false);
    nextProps.mod.parameters["client-enc-parameter"]!==undefined?"":(nextProps.mod.parameters["client-enc-parameter"] = "enc");
    nextProps.mod.parameters["client-alg-parameter"]!==undefined?"":(nextProps.mod.parameters["client-alg-parameter"] = "alg");
    nextProps.mod.parameters["client-alg_kid-parameter"]!==undefined?"":(nextProps.mod.parameters["client-alg_kid-parameter"] = "alg_kid");
    nextProps.mod.parameters["client-encrypt_code-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_code-parameter"] = "encrypt_code");
    nextProps.mod.parameters["client-encrypt_at-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_at-parameter"] = "encrypt_at");
    nextProps.mod.parameters["client-encrypt_userinfo-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_userinfo-parameter"] = "encrypt_userinfo");
    nextProps.mod.parameters["client-encrypt_id_token-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_id_token-parameter"] = "encrypt_id_token");
    nextProps.mod.parameters["client-encrypt_refresh_token-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_refresh_token-parameter"] = "encrypt_refresh_token");
    nextProps.mod.parameters["client-encrypt_introspection-parameter"]!==undefined?"":(nextProps.mod.parameters["client-encrypt_introspection-parameter"] = "encrypt_introspection");
    nextProps.mod.parameters["device-authorization-expiration"]!==undefined?"":(nextProps.mod.parameters["device-authorization-expiration"] = 600);
    nextProps.mod.parameters["device-authorization-interval"]!==undefined?"":(nextProps.mod.parameters["device-authorization-interval"] = 5);
    nextProps.mod.parameters["client-cert-header-name"]!==undefined?"":(nextProps.mod.parameters["client-cert-header-name"] = "SSL_CLIENT_CERT");
    nextProps.mod.parameters["client-cert-use-endpoint-aliases"]!==undefined?"":(nextProps.mod.parameters["client-cert-use-endpoint-aliases"] = false);
    nextProps.mod.parameters["client-cert-self-signed-allowed"]!==undefined?"":(nextProps.mod.parameters["client-cert-self-signed-allowed"] = false);
    nextProps.mod.parameters["oauth-dpop-allowed"]!==undefined?"":(nextProps.mod.parameters["oauth-dpop-allowed"] = false);
    nextProps.mod.parameters["oauth-dpop-iat-duration"]!==undefined?"":(nextProps.mod.parameters["oauth-dpop-iat-duration"] = 10);
    nextProps.mod.parameters["resource-allowed"]!==undefined?"":(nextProps.mod.parameters["resource-allowed"] = false);
    nextProps.mod.parameters["resource-scope"]!==undefined?"":(nextProps.mod.parameters["resource-scope"] = {});
    nextProps.mod.parameters["resource-client-property"]!==undefined?"":(nextProps.mod.parameters["resource-client-property"] = "");
    nextProps.mod.parameters["resource-scope-and-client-property"]!==undefined?"":(nextProps.mod.parameters["resource-scope-and-client-property"] = false);
    nextProps.mod.parameters["resource-change-allowed"]!==undefined?"":(nextProps.mod.parameters["resource-change-allowed"] = false);
    nextProps.mod.parameters["oauth-rar-allowed"]!==undefined?"":(nextProps.mod.parameters["oauth-rar-allowed"] = false);
    nextProps.mod.parameters["rar-types-client-property"]!==undefined?"":(nextProps.mod.parameters["rar-types-client-property"] = "authorization_data_types");
    nextProps.mod.parameters["rar-allow-auth-unsigned"]!==undefined?"":(nextProps.mod.parameters["rar-allow-auth-unsigned"] = false);
    nextProps.mod.parameters["rar-allow-auth-unencrypted"]!==undefined?"":(nextProps.mod.parameters["rar-allow-auth-unencrypted"] = true);
    nextProps.mod.parameters["rar-types"]!==undefined?"":(nextProps.mod.parameters["rar-types"] = {});

    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }

  changeParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = e.target.value;
    this.setState({mod: mod});
  }

  changeParamWithValue(param, value) {
    var mod = this.state.mod;
    mod.parameters[param] = value;
    this.setState({mod: mod});
  }

  changeNumberParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = parseInt(e.target.value);
    if (!isNaN(mod.parameters[param])) {
      this.setState({mod: mod});
    }
  }

  emptyParameter(param) {
    var mod = this.state.mod;
    delete mod.parameters[param];
    this.setState({mod: mod});
  }

  toggleParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }

  changeJwtType(e, type) {
    var mod = this.state.mod;
    mod.parameters["jwt-type"] = type;
    this.setState({mod: mod});
  }

  changeSecretType(e, type) {
    var mod = this.state.mod;
    mod.parameters["secret-type"] = type;
    this.setState({mod: mod});
  }

  changeJwtKeySize(e, size) {
    var mod = this.state.mod;
    mod.parameters["jwt-key-size"] = size;
    this.setState({mod: mod});
  }

  uploadFile(e, name) {
    var mod = this.state.mod;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      mod.parameters[name] = ev2.target.result;
      this.setState({mod: mod});
    };
    fr.readAsText(file);
  }

  uploadX5cFile(e) {
    var mod = this.state.mod;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      mod.parameters["jwks-x5c"].push(ev2.target.result);
      this.setState({mod: mod});
    };
    fr.readAsText(file);
  }

  handleRemoveX5c(e, index) {
    e.preventDefault();
    if (this.state.mod.parameters["jwks-show"]) {
      var mod = this.state.mod;
      mod.parameters["jwks-x5c"].splice(index, 1);
      this.setState({mod: mod});
    }
  }

  setNewScopeOverride(e, scope) {
    this.setState({newScopeOverride: scope});
  }

  addScopeOverride() {
    if (this.state.newScopeOverride) {
      var mod = this.state.mod;
      mod.parameters["scope"].push({
        name: this.state.newScopeOverride,
        "refresh-token-rolling": this.state.mod.parameters["refresh-token-rolling"],
        "refresh-token-duration": 0
      });
      this.setState({mod: mod, newScopeOverride: false});
    }
  }

  changeScopeOverrideRefreshDuration(e, scope) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope) => {
      if (curScope.name === scope.name) {
        curScope["refresh-token-duration"] = parseInt(e.target.value);
      }
    });
    this.setState({mod: mod});
  }

  toggleScopeOverrideRolling(e, scope, value) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope) => {
      if (curScope.name === scope) {
        if (value === undefined) {
          delete (curScope["refresh-token-rolling"]);
        } else {
          curScope["refresh-token-rolling"] = value;
        }
      }
    });
    this.setState({mod: mod});
  }

  deleteScopeOverride(e, scope) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope, index) => {
      if (curScope.name === scope) {
        mod.parameters["scope"].splice(index, 1);
      }
    });
    this.setState({mod: mod});
  }

  addAdditionalParameter() {
    var mod = this.state.mod;
    mod.parameters["additional-parameters"].push({
      "user-parameter": "",
      "token-parameter": "",
      "token-changed": false
    });
    this.setState({mod: mod, newScopeOverride: false});
  }

  setAdditionalPropertyUserParameter(e, index) {
    var mod = this.state.mod;
    if (mod.parameters["additional-parameters"][index]) {
      mod.parameters["additional-parameters"][index]["user-parameter"] = e.target.value;
      if (!mod.parameters["additional-parameters"][index]["token-changed"]) {
        mod.parameters["additional-parameters"][index]["token-parameter"] = e.target.value;
      }
    }
    this.setState({mod: mod, newScopeOverride: false});
  }

  setAdditionalPropertyTokenParameter(e, index) {
    var mod = this.state.mod;
    if (mod.parameters["additional-parameters"][index]) {
      mod.parameters["additional-parameters"][index]["token-parameter"] = e.target.value;
      mod.parameters["additional-parameters"][index]["token-changed"] = true;
    }
    this.setState({mod: mod, newScopeOverride: false});
  }

  deleteAdditionalProperty(e, index) {
    var mod = this.state.mod;
    if (mod.parameters["additional-parameters"][index]) {
      mod.parameters["additional-parameters"].splice(index, 1);
    }
    this.setState({mod: mod, newScopeOverride: false});
  }

  addClaim() {
    var mod = this.state.mod;
    mod.parameters["claims"].push({
      "name": "",
      "user-property": "",
      "type": "string",
      "boolean-value-true": "",
      "boolean-value-false": "",
      "mandatory": false,
      "on-demand": false,
      scope: []
    });
    this.setState({mod: mod});
  }

  deleteClaim(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"].splice(index, 1);
    this.setState({mod: mod});
  }

  setClaimName(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["name"] = e.target.value;
    this.setState({mod: mod});
  }

  setClaimUserProperty(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["user-property"] = e.target.value;
    this.setState({mod: mod});
  }

  setClaimType(e, index, type) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["type"] = type;
    this.setState({mod: mod});
  }

  setClaimBooleanTrue(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["boolean-value-true"] = e.target.value;
    this.setState({mod: mod});
  }

  setClaimBooleanFalse(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["boolean-value-false"] = e.target.value;
    this.setState({mod: mod});
  }

  toggleClaimMandatory(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["mandatory"] = !mod.parameters["claims"][index]["mandatory"];
    this.setState({mod: mod});
  }

  toggleClaimOnDemand(e, index) {
    var mod = this.state.mod;
    mod.parameters["claims"][index]["on-demand"] = !mod.parameters["claims"][index]["on-demand"];
    this.setState({mod: mod});
  }

  changeAddressClaimParam(e, param) {
    var mod = this.state.mod;
    mod.parameters["address-claim"][param] = e.target.value;
    this.setState({mod: mod});
  }

  changeAddressClaim(e, type) {
    var mod = this.state.mod;
    mod.parameters["address-claim"].type = type;
    this.setState({mod: mod});
  }

  toggleAddrClaimMandatory(e, index) {
    var mod = this.state.mod;
    mod.parameters["address-claim"].mandatory = !mod.parameters["address-claim"].mandatory;
    this.setState({mod: mod});
  }

  addScopeClaim(e, index, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["claims"][index].scope.push(scope);
    this.setState({mod: mod});
  }

  deleteScopeClaim(e, index, indexScope) {
    e.preventDefault();
    if (!this.state.mod.parameters["claims"][index].mandatory) {
      var mod = this.state.mod;
      mod.parameters["claims"][index].scope.splice(indexScope, 1);
      this.setState({mod: mod});
    }
  }

  addNameScope(e, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["name-claim-scope"].push(scope);
    this.setState({mod: mod});
  }

  deleteNameScope(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["name-claim-scope"].splice(index, 1);
    this.setState({mod: mod});
  }

  addEmailScope(e, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["email-claim-scope"].push(scope);
    this.setState({mod: mod});
  }

  deleteEmailScope(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["email-claim-scope"].splice(index, 1);
    this.setState({mod: mod});
  }

  addAllowedScope(e, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    if (scope) {
      mod.parameters["allowed-scope"].push(scope);
    } else {
      mod.parameters["allowed-scope"] = ["openid"];
      this.state.config.scopes.forEach((scope) => {
        if (scope.name !== "openid") {
          mod.parameters["allowed-scope"].push(scope.name);
        }
      });
    }
    this.setState({mod: mod});
  }

  deleteAllowedScope(e, index) {
    e.preventDefault();
    if (this.state.mod.parameters["allowed-scope"][index] !== "openid") {
      var mod = this.state.mod;
      mod.parameters["allowed-scope"].splice(index, 1);
      this.setState({mod: mod});
    }
  }

  addScope(e, param, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters[param].push(scope);
    this.setState({mod: mod});
  }

  deleteScope(e, param, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters[param].splice(index, 1);
    this.setState({mod: mod});
  }

  changeMtlsClientSource(e, source) {
    var mod = this.state.mod;
    if (source) {
      mod.parameters["client-cert-source"] = source;
    } else {
      delete(mod.parameters["client-cert-source"]);
    }
    this.setState({mod: mod});
  }

  setResourceScope(e, scope) {
    e.preventDefault();
    this.setState({newResourceScope: scope});
  }

  addResourceScope() {
    var mod = this.state.mod;
    mod.parameters["resource-scope"][this.state.newResourceScope] = [];
    this.setState({mod: mod, newResourceScope: false});
  }

  changeResourceScopeUrls(e, scope) {
    var mod = this.state.mod;
    mod.parameters["resource-scope"][scope] = e.target.value.split("\n");
    this.setState({mod: mod});
  }

  deleteResourceScope(e, scope) {
    var mod = this.state.mod;
    delete(mod.parameters["resource-scope"][scope]);
    this.setState({mod: mod});
  }

  changeRegisterResourceDefaultUrls(e) {
    var mod = this.state.mod;
    mod.parameters["register-resource-default"] = e.target.value.split("\n");
    this.setState({mod: mod});
  }

  setNewRar(e) {
    var newRarExists = false;
    var newRarInvalidChar = false;
    var regexp = /^[a-zA-Z0-9-_\$]+$/;
    
    if (this.state.mod.parameters["rar-types"][e.target.value]) {
      newRarExists = true;
    }
    if (e.target.value && e.target.value.search(regexp) === -1) {
      newRarInvalidChar = true;
    }
    this.setState({newRar: e.target.value, newRarExists: newRarExists, newRarInvalidChar: newRarInvalidChar});
  }

  addRAR() {
    var mod = this.state.mod;
    if (!mod.parameters["rar-types"][this.state.newRar]) {
      mod.parameters["rar-types"][this.state.newRar] = {
        scopes: [],
        locations: [],
        actions: [],
        datatypes: [],
        enriched: []
      };
      this.setState({mod: mod, newRar: ""});
    }
  }
  
  changeRarParameter(e, type, parameter) {
    var mod = this.state.mod;
    if (parameter === "description") {
      mod.parameters["rar-types"][type][parameter] = e.target.value;
    } else {
      mod.parameters["rar-types"][type][parameter] = e.target.value.split("\n");
    }
    this.setState({mod: mod});
  }
  
  deleteRar(e, type) {
    var mod = this.state.mod;
    delete(mod.parameters["rar-types"][type]);
    this.setState({mod: mod});
  }
  
  addRarTypeScope(e, type, scope) {
    var mod = this.state.mod;
    mod.parameters["rar-types"][type].scopes.push(scope);
    this.setState({mod: mod});
  }
  
  deleteRarTypeScope(e, type, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["rar-types"][type].scopes.splice(mod.parameters["rar-types"][type].scopes.indexOf(scope), 1);
    this.setState({mod: mod});
  }

  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["iss"]) {
      hasError = true;
      errorList["iss"] = i18next.t("admin.mod-glwd-iss-error");
      errorList["general"] = true;
    }
    if (!this.state.mod.parameters["jwks-private"] && !this.state.mod.parameters["jwks-uri"]) {
      if (!this.state.mod.parameters["key"]) {
        hasError = true;
        errorList["key"] = i18next.t("admin.mod-glwd-key-error");
        errorList["signature"] = true;
      }
      if (this.state.mod.parameters["jwt-type"] !== "sha" && !this.state.mod.parameters["cert"]) {
        hasError = true;
        errorList["cert"] = i18next.t("admin.mod-glwd-cert-error");
        errorList["signature"] = true;
      }
    } else if (this.state.mod.parameters["jwks-private"]) {
      var jwks = false;
      try {
        jwks = JSON.parse(this.state.mod.parameters["jwks-private"]);
      } catch (e) {
        hasError = true;
        errorList["jwks-private"] = i18next.t("admin.mod-glwd-jwks-error");
        errorList["signature"] = true;
      }
      if (jwks) {
        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          hasError = true;
          errorList["jwks-private"] = i18next.t("admin.mod-glwd-jwks-error");
          errorList["signature"] = true;
        } else if (this.state.mod.parameters["default-kid"]) {
          var kidFound = false;
          jwks.keys.forEach((key) => {
            if (key.kid === this.state.mod.parameters["default-kid"]) {
              kidFound = true;
            }
          });
          if (!kidFound) {
            hasError = true;
            errorList["default-kid"] = i18next.t("admin.mod-glwd-default-kid-error");
            errorList["signature"] = true;
          }
        }
      }
    }
    if (this.state.mod.parameters["jwks-public"]) {
      var jwks = false;
      try {
        jwks = JSON.parse(this.state.mod.parameters["jwks-public"]);
      } catch (e) {
        hasError = true;
        errorList["jwks-public"] = i18next.t("admin.mod-glwd-jwks-error");
        errorList["signature"] = true;
      }
      if (jwks) {
        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          hasError = true;
          errorList["jwks-public"] = i18next.t("admin.mod-glwd-jwks-error");
          errorList["signature"] = true;
        }
      }
    }

    if (!this.state.mod.parameters["access-token-duration"]) {
      hasError = true;
      errorList["access-token-duration"] = i18next.t("admin.mod-glwd-access-token-duration-error");
      errorList["token"] = true;
    }
    if (!this.state.mod.parameters["refresh-token-duration"]) {
      hasError = true;
      errorList["refresh-token-duration"] = i18next.t("admin.mod-glwd-refresh-token-duration-error");
      errorList["token"] = true;
    }
    if (!this.state.mod.parameters["code-duration"]) {
      hasError = true;
      errorList["code-duration"] = i18next.t("admin.mod-glwd-code-duration-error");
      errorList["token"] = true;
    }
    this.state.mod.parameters["additional-parameters"].forEach((addParam, index) => {
      if (!addParam["user-parameter"]) {
        hasError = true;
        if (!errorList["additional-parameters"]) {
          errorList["additional-parameters"] = [];
        }
        if (!errorList["additional-parameters"][index]) {
          errorList["additional-parameters"][index] = {};
        }
        errorList["additional-parameters"][index]["user"] = i18next.t("admin.mod-glwd-additional-parameter-user-parameter-error");
      }
      if (!addParam["token-parameter"]) {
        hasError = true;
        if (!errorList["additional-parameters"]) {
          errorList["additional-parameters"] = [];
        }
        if (!errorList["additional-parameters"][index]) {
          errorList["additional-parameters"][index] = {};
        }
        errorList["additional-parameters"][index]["token"] = i18next.t("admin.mod-glwd-additional-parameter-token-parameter-error");
      } else if (addParam["token-parameter"] === "username" ||
                 addParam["token-parameter"] === "salt" ||
                 addParam["token-parameter"] === "type" ||
                 addParam["token-parameter"] === "iat" ||
                 addParam["token-parameter"] === "expires_in" ||
                 addParam["token-parameter"] === "scope") {
        hasError = true;
        if (!errorList["additional-parameters"]) {
          errorList["additional-parameters"] = [];
        }
        if (!errorList["additional-parameters"][index]) {
          errorList["additional-parameters"][index] = {};
        }
        errorList["additional-parameters"][index]["token"] = i18next.t("admin.mod-glwd-additional-parameter-token-parameter-invalid-error");
      }
    });
    this.state.mod.parameters["claims"].forEach((claimParam, index) => {
      if (claimParam["name"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["name"] = i18next.t("admin.mod-glwd-claims-name-error");
      } else if (["iss","sub","aud","exp","iat","auth_time","nonce","acr","amr","azp","name","email","address"].indexOf(claimParam["name"]) > -1) {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["name"] = i18next.t("admin.mod-glwd-claims-name-forbidden-error");
      }
      if (claimParam["user-property"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["user-property"] = i18next.t("admin.mod-glwd-claims-user-property-error");
      }
      if (claimParam["type"] === "boolean" && claimParam["boolean-value-true"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["boolean-value-true"] = i18next.t("admin.mod-glwd-claims-boolean-value-true-error");
      }
      if (claimParam["type"] === "boolean" && claimParam["boolean-value-false"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["boolean-value-false"] = i18next.t("admin.mod-glwd-claims-boolean-value-false-error");
      }
    });
    if (this.state.mod.parameters["introspection-revocation-allowed"] && !this.state.mod.parameters["introspection-revocation-allow-target-client"] && !this.state.mod.parameters["introspection-revocation-auth-scope"].length) {
      hasError = true;
      errorList["introspection-revocation"] = i18next.t("admin.mod-glwd-introspection-revocation-error");
      errorList["token"] = true;
    }
    if (this.state.mod.parameters["oauth-dpop-allowed"] && !this.state.mod.parameters["oauth-dpop-iat-duration"]) {
      hasError = true;
      errorList["oauth-dpop-iat-duration"] = i18next.t("admin.mod-glwd-oauth-dpop-iat-duration-error");
      errorList["oauth-dpop"] = true;
    }
    if (this.state.mod.parameters["resource-allowed"]) {
      var nbScopes = 0;
      Object.keys(this.state.mod.parameters["resource-scope"]).forEach(scope => {
        nbScopes++;
        if (!this.state.mod.parameters["resource-scope"][scope].length) {
          hasError = true;
          if (!errorList["resource-scope"]) {
            errorList["resource-scope"] = {};
          }
          errorList["resource-scope"][scope] = i18next.t("admin.mod-glwd-resource-scope-empty-error");
          errorList["resource"] = true;
        } else {
          this.state.mod.parameters["resource-scope"][scope].forEach((url, index) => {
            if (!url.startsWith("https://") && !url.startsWith("http://localhost") && !url.startsWith("http://127.0.0.1") && !url.startsWith("http://[::1]")) {
              hasError = true;
              if (!errorList["resource-scope"]) {
                errorList["resource-scope"] = {};
              }
              errorList["resource-scope"][scope] = i18next.t("admin.mod-glwd-resource-scope-url-error");
              errorList["resource"] = true;
            } else if (url.indexOf("#") > -1) {
              hasError = true;
              if (!errorList["resource-scope"]) {
                errorList["resource-scope"] = {};
              }
              errorList["resource-scope"][scope] = i18next.t("admin.mod-glwd-resource-scope-url-error");
              errorList["resource"] = true;
            }
          });
        }
      });
      if (!nbScopes && !this.state.mod.parameters["resource-client-property"]) {
        hasError = true;
        errorList["resource-scope-or-client"] = i18next.t("admin.mod-glwd-resource-scope-or-client-error");
        errorList["resource"] = true;
      }
      if (this.state.mod.parameters["resource-scope-and-client-property"] && (!nbScopes || !this.state.mod.parameters["resource-client-property"])) {
        hasError = true;
        errorList["resource-scope-or-client"] = i18next.t("admin.mod-glwd-resource-scope-and-client-error");
        errorList["resource"] = true;
      }
    }
    if (this.state.mod.parameters["oauth-rar-allowed"]) {
      if (!this.state.mod.parameters["rar-types-client-property"]) {
        hasError = true;
        errorList["rar-types-client-property"] = i18next.t("admin.mod-glwd-rar-types-client-property-error");
        errorList["oauth-rar"] = true;
      }
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modInvalid"});
      });
    }
  }

  render() {
    var keyJsx, certJsx, scopeOverrideList = [], scopeList = [], additionalParametersList = [], claimsList = [], x5cList = [], addressClaim;
    var baseApiUrl = document.location.href.split('?')[0].split('#')[0] + this.state.config.api_prefix + "/" + (this.state.mod.name||"");
    var urlOidcConfig = baseApiUrl + "/.well-known/openid-configuration", urlAuth = baseApiUrl + "/auth", urlToken = baseApiUrl + "/token", urlUserinfo = baseApiUrl + "/userinfo";
    if (this.state.mod.parameters["jwt-type"] === "sha") {
      keyJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-glwd-key">{i18next.t("admin.mod-glwd-key")}</label>
            </div>
            <input type="password" className={this.state.errorList["key"]?"form-control is-invalid":"form-control"} id="mod-glwd-key" onChange={(e) => this.changeParam(e, "key")} value={this.state.mod.parameters["key"]} placeholder={i18next.t("admin.mod-glwd-key-ph")} />
          </div>
          {this.state.errorList["key"]?<span className="error-input">{this.state.errorList["key"]}</span>:""}
        </div>;
    } else {
      keyJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-glwd-key">{i18next.t("admin.mod-glwd-key")}</label>
            </div>
            <div className="custom-file">
              <input type="file" id="mod-glwd-key" className={this.state.errorList["key"]?"custom-file-input is-invalid":"custom-file-input"} onChange={(e) => this.uploadFile(e, "key")} />
              <label className="custom-file-label" htmlFor="mod-glwd-key">{i18next.t("admin.choose-file")}</label>
            </div>
          </div>
          {this.state.mod.parameters["key"]?<div className="alert alert-primary">{this.state.mod.parameters["key"].substring(0, 40)}<button type="button" onClick={(e) => this.emptyParameter("key")} className="close"><span aria-hidden="true"><i className="fas fa-trash"></i></span></button></div>:""}
          {this.state.errorList["key"]?<span className="error-input">{this.state.errorList["key"]}</span>:""}
        </div>;
      certJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-glwd-cert">{i18next.t("admin.mod-glwd-cert")}</label>
            </div>
            <div className="custom-file">
              <input type="file" id="mod-glwd-cert" className={this.state.errorList["key"]?"custom-file-input is-invalid":"custom-file-input"} onChange={(e) => this.uploadFile(e, "cert")} />
              <label className="custom-file-label" htmlFor="mod-glwd-cert">{i18next.t("admin.choose-file")}</label>
            </div>
          </div>
          {this.state.mod.parameters["cert"]?<div className="alert alert-primary">{this.state.mod.parameters["cert"].substring(0, 40)}<button type="button" onClick={(e) => this.emptyParameter("cert")} className="close"><span aria-hidden="true"><i className="fas fa-trash"></i></span></button></div>:""}
          {this.state.errorList["cert"]?<span className="error-input">{this.state.errorList["cert"]}</span>:""}
        </div>;
    }
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          var found = 0;
          this.state.mod.parameters["scope"].forEach((curScope) => {
            if (curScope.name === scope) {
              found = 1;
            }
          });
          if (!found) {
            scopeList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.setNewScopeOverride(e, scope)}>{scope}</a>);
          }
        });
      }
    });
    var scopeJsx =
      <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-scope-override-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          {this.state.newScopeOverride||i18next.t("admin.mod-glwd-scope-override-scope")}
        </button>
        <div className="dropdown-menu" aria-labelledby="mod-glwd-scope-override-scope">
          {scopeList}
        </div>
      </div>;
    this.state.mod.parameters["scope"].forEach((scope, index) => {
      scopeOverrideList.push(
      <div key={index}>
        <hr/>
        <h4>{scope.name}</h4>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-scope-override-refresh-duration-"+scope.name}>{i18next.t("admin.mod-glwd-scope-override-refresh-duration")}</label>
            </div>
            <input type="number" min="0" step="1" className="form-control" id={"mod-glwd-scope-override-refresh-duration-"+scope.name} onChange={(e) => this.changeScopeOverrideRefreshDuration(e, scope)} value={scope["refresh-token-duration"]} placeholder={i18next.t("admin.mod-glwd-scope-override-refresh-duration-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-scope-override-refresh-rolling-"+scope.name}>{i18next.t("admin.mod-scope-override-refresh-rolling")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-glwd-scope-override-refresh-rolling-"+scope.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.glwd-scope-override-refresh-rolling-value-" + scope["refresh-token-rolling"])}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-type">
                <a className={"dropdown-item"+(scope["refresh-token-rolling"]===undefined?" active":"")} href="#" onClick={(e) => this.toggleScopeOverrideRolling(e, scope.name, undefined)}>{i18next.t("admin.glwd-scope-override-refresh-rolling-value-undefined")}</a>
                <a className={"dropdown-item"+(scope["refresh-token-rolling"]===true?" active":"")} href="#" onClick={(e) => this.toggleScopeOverrideRolling(e, scope.name, true)}>{i18next.t("admin.glwd-scope-override-refresh-rolling-value-true")}</a>
                <a className={"dropdown-item"+(scope["refresh-token-rolling"]===false?" active":"")} href="#" onClick={(e) => this.toggleScopeOverrideRolling(e, scope.name, false)}>{i18next.t("admin.glwd-scope-override-refresh-rolling-value-false")}</a>
              </div>
            </div>
          </div>
        </div>
        <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteScopeOverride(e, scope.name)} title={i18next.t("admin.mod-scope-override-delete")}>
          <i className="fas fa-trash"></i>
        </button>
      </div>
      );
    });

    this.state.mod.parameters["additional-parameters"].forEach((parameter, index) => {
      var hasUserError = this.state.errorList["additional-parameters"] && this.state.errorList["additional-parameters"][index] && this.state.errorList["additional-parameters"][index]["user"];
      var hasTokenError = this.state.errorList["additional-parameters"] && this.state.errorList["additional-parameters"][index] && this.state.errorList["additional-parameters"][index]["token"];
      additionalParametersList.push(
      <div key={index}>
        <hr/>
        <h4>{parameter["user-parameter"]||i18next.t("admin.mod-additional-parameter-new")}</h4>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-additional-parameter-user-parameter-"+parameter["user-parameter"]}>{i18next.t("admin.mod-glwd-additional-parameter-user-parameter")}</label>
            </div>
            <input type="text" className={hasUserError?"form-control is-invalid":"form-control"} id={"mod-glwd-additional-parameter-user-parameter-"+parameter["user-parameter"]} onChange={(e) => this.setAdditionalPropertyUserParameter(e, index)} value={parameter["user-parameter"]} placeholder={i18next.t("admin.mod-glwd-additional-parameter-user-parameter-ph")} />
            {hasUserError?<span className="error-input">{this.state.errorList["additional-parameters"][index]["user"]}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-additional-parameter-token-parameter-"+parameter["token-parameter"]}>{i18next.t("admin.mod-glwd-additional-parameter-token-parameter")}</label>
            </div>
            <input type="text" className={hasTokenError?"form-control is-invalid":"form-control"} id={"mod-glwd-additional-parameter-token-parameter-"+parameter["token-parameter"]} onChange={(e) => this.setAdditionalPropertyTokenParameter(e, index)} value={parameter["token-parameter"]} placeholder={i18next.t("admin.mod-glwd-additional-parameter-token-parameter-ph")} />
          </div>
          {hasTokenError?<span className="error-input">{this.state.errorList["additional-parameters"][index]["token"]}</span>:""}
        </div>
        <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteAdditionalProperty(e, index)} title={i18next.t("admin.mod-additional-parameter-token-delete")}>
          <i className="fas fa-trash"></i>
        </button>
      </div>
      );
    });

    var allowedScopeListToAdd = [<a className="dropdown-item" key={-1} href="#" onClick={(e) => this.addAllowedScope(e, false)}>{i18next.t("admin.mod-glwd-allowed-scope-all")}</a>];
    this.state.config.scopes.forEach((scope, indexScope) => {
      if (this.state.mod.parameters["allowed-scope"].indexOf(scope.name) === -1 && scope.name !== "openid") {
        allowedScopeListToAdd.push(
          <a className="dropdown-item" key={indexScope} href="#" onClick={(e) => this.addAllowedScope(e, scope.name)}>{scope.name}</a>
        );
      }
    });

    var allowedScopeList = [];
    this.state.mod.parameters["allowed-scope"].forEach((scope, indexScope) => {
      allowedScopeList.push(
        <a href="#" onClick={(e) => this.deleteAllowedScope(e, indexScope)} key={indexScope}><span className="badge badge-primary btn-icon-right">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>
      );
    });

    var nameScopeListToAdd = [];
    this.state.config.scopes.forEach((scope, indexScope) => {
      if (this.state.mod.parameters["name-claim-scope"].indexOf(scope.name) === -1) {
        nameScopeListToAdd.push(
          <a className="dropdown-item" key={indexScope} href="#" onClick={(e) => this.addNameScope(e, scope.name)}>{scope.name}</a>
        );
      }
    });

    var nameScopeList = [];
    this.state.mod.parameters["name-claim-scope"].forEach((scope, indexScope) => {
      nameScopeList.push(
        <a href="#" onClick={(e) => this.deleteNameScope(e, indexScope)} key={indexScope}><span className="badge badge-primary btn-icon-right">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>
      );
    });

    var emailScopeListToAdd = [];
    this.state.config.scopes.forEach((scope, indexScope) => {
      if (this.state.mod.parameters["email-claim-scope"].indexOf(scope.name) === -1) {
        emailScopeListToAdd.push(
          <a className="dropdown-item" key={indexScope} href="#" onClick={(e) => this.addEmailScope(e, scope.name)}>{scope.name}</a>
        );
      }
    });

    var emailScopeList = [];
    this.state.mod.parameters["email-claim-scope"].forEach((scope, indexScope) => {
      emailScopeList.push(
        <a href="#" onClick={(e) => this.deleteEmailScope(e, indexScope)} key={indexScope}><span className="badge badge-primary btn-icon-right">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>
      );
    });

    var scopeScopeListToAdd = [];
    this.state.config.scopes.forEach((scope, indexScope) => {
      if (this.state.mod.parameters["scope-claim-scope"].indexOf(scope.name) === -1) {
        scopeScopeListToAdd.push(
          <a className="dropdown-item" key={indexScope} href="#" onClick={(e) => this.addEmailScope(e, scope.name)}>{scope.name}</a>
        );
      }
    });

    var scopeScopeList = [];
    this.state.mod.parameters["scope-claim-scope"].forEach((scope, indexScope) => {
      scopeScopeList.push(
        <a href="#" onClick={(e) => this.deleteEmailScope(e, indexScope)} key={indexScope}><span className="badge badge-primary btn-icon-right">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>
      );
    });

    this.state.mod.parameters["jwks-x5c"].forEach((x5c, index) => {
      x5cList.push(
        <a disabled={!this.state.mod.parameters["jwks-show"]} href="#" key={index} onClick={(e) => this.handleRemoveX5c(e, index)}>
          <span className="badge badge-primary btn-icon-right">
            {x5c.substring(0, 40)}
            <span className="badge badge-light btn-icon-right">
              <i className="fas fa-times"></i>
            </span>
          </span>
        </a>
      );
    });

    this.state.mod.parameters["claims"].forEach((parameter, index) => {
      var hasNameError = this.state.errorList["claims"] && this.state.errorList["claims"][index] && this.state.errorList["claims"][index]["name"];
      var hasUserPropertyError = this.state.errorList["claims"] && this.state.errorList["claims"][index] && this.state.errorList["claims"][index]["user-property"];
      var hasBooleanTrueError = this.state.errorList["claims"] && this.state.errorList["claims"][index] && this.state.errorList["claims"][index]["boolean-value-true"];
      var hasBooleanFalseError = this.state.errorList["claims"] && this.state.errorList["claims"][index] && this.state.errorList["claims"][index]["boolean-value-false"];
      var booleanValues = "";
      if (parameter["type"]==="boolean") {
        booleanValues = <div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-glwd-claims-boolean-value-true-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-boolean-value-true")}</label>
              </div>
              <input type="text" className={hasBooleanTrueError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-boolean-value-true-"+parameter["name"]} onChange={(e) => this.setClaimBooleanTrue(e, index)} value={parameter["boolean-value-true"]} placeholder={i18next.t("admin.mod-glwd-claims-boolean-value-true-ph")} />
              {hasBooleanTrueError?<span className="error-input">{this.state.errorList["claims"][index]["boolean-value-true"]}</span>:""}
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-glwd-claims-boolean-value-false-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-boolean-value-false")}</label>
              </div>
              <input type="text" className={hasBooleanFalseError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-boolean-value-false-"+parameter["name"]} onChange={(e) => this.setClaimBooleanFalse(e, index)} value={parameter["boolean-value-false"]} placeholder={i18next.t("admin.mod-glwd-claims-boolean-value-false-ph")} />
              {hasBooleanFalseError?<span className="error-input">{this.state.errorList["claims"][index]["boolean-value-false"]}</span>:""}
            </div>
          </div>
        </div>
      }
      var scopeList = [];
      this.state.config.scopes.forEach((scope, indexScope) => {
        if (parameter["scope"].indexOf(scope.name) === -1) {
          scopeList.push(
            <a className="dropdown-item" key={indexScope} href="#" onClick={(e) => this.addScopeClaim(e, index, scope.name)}>{scope.name}</a>
          );
        }
      });
      var selectedScopeList = [];
      parameter["scope"].forEach((scope, indexScope) => {
        selectedScopeList.push(
          <a href="#" onClick={(e) => this.deleteScopeClaim(e, index, indexScope)} key={indexScope}><span className="badge badge-primary btn-icon-right">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>
        );
      });
      claimsList.push(
      <div key={index}>
        <hr/>
        <h4>{parameter["name"]||i18next.t("admin.mod-claims-new")}</h4>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-claims-name-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-name")}</label>
            </div>
            <input type="text" className={hasNameError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-name-"+parameter["name"]} onChange={(e) => this.setClaimName(e, index)} value={parameter["name"]} placeholder={i18next.t("admin.mod-glwd-claims-name-ph")} />
            {hasNameError?<span className="error-input">{this.state.errorList["claims"][index]["name"]}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-claims-user-property-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-user-property")}</label>
            </div>
            <input type="text" className={hasUserPropertyError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-user-property-"+parameter["name"]} onChange={(e) => this.setClaimUserProperty(e, index)} value={parameter["user-property"]} placeholder={i18next.t("admin.mod-glwd-claims-user-property-ph")} />
            {hasUserPropertyError?<span className="error-input">{this.state.errorList["claims"][index]["user-property"]}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-glwd-claims-type">{i18next.t("admin.mod-glwd-claims-type")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-glwd-claims-type-"+parameter["name"]} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-glwd-claims-type-" + parameter["type"])}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-glwd-claims-type">
                <a className={"dropdown-item"+(parameter["type"]==="string"?" active":"")} href="#" onClick={(e) => this.setClaimType(e, index, 'string')}>{i18next.t("admin.mod-glwd-claims-type-string")}</a>
                <a className={"dropdown-item"+(parameter["type"]==="number"?" active":"")} href="#" onClick={(e) => this.setClaimType(e, index, 'number')}>{i18next.t("admin.mod-glwd-claims-type-number")}</a>
                <a className={"dropdown-item"+(parameter["type"]==="boolean"?" active":"")} href="#" onClick={(e) => this.setClaimType(e, index, 'boolean')}>{i18next.t("admin.mod-glwd-claims-type-boolean")}</a>
              </div>
            </div>
          </div>
          {booleanValues}
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id={"mod-glwd-claims-mandatory-"+parameter["name"]} onChange={(e) => this.toggleClaimMandatory(e, index)} checked={parameter["mandatory"]} />
            <label className="form-check-label" htmlFor={"mod-glwd-claims-mandatory-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-mandatory")}</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id={"mod-glwd-claims-on-demand-"+parameter["name"]} onChange={(e) => this.toggleClaimOnDemand(e, index)} checked={parameter["on-demand"]} disabled={parameter["mandatory"]}/>
            <label disabled={true} className="form-check-label" htmlFor={"mod-glwd-claims-on-demand-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-on-demand")}</label>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-scope-claim">{i18next.t("admin.mod-glwd-scope-claim")}</label>
              </div>
              <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-scope-claim" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={parameter["mandatory"]}>
                  {i18next.t("admin.mod-glwd-scope-claim-select")}
                </button>
                <div className="dropdown-menu" aria-labelledby="mod-glwd-name-email-claim">
                  {scopeList}
                </div>
              </div>
              {selectedScopeList}
            </div>
          </div>
        </div>
        <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteClaim(e, index)} title={i18next.t("admin.mod-claims-delete")}>
          <i className="fas fa-trash"></i>
        </button>
      </div>
      );
    });

    if (this.state.mod.parameters["address-claim"].type!=="no") {
      addressClaim =
        <div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-formatted">{i18next.t("admin.mod-glwd-addr-claim-formatted")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-formatted" onChange={(e) => this.changeAddressClaimParam(e, "formatted")} value={this.state.mod.parameters["address-claim"]["formatted"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-formatted-ph")} />
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-street-address">{i18next.t("admin.mod-glwd-addr-claim-street-address")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-street-address" onChange={(e) => this.changeAddressClaimParam(e, "street_address")} value={this.state.mod.parameters["address-claim"]["street_address"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-street-address-ph")} />
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-locality">{i18next.t("admin.mod-glwd-addr-claim-locality")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-locality" onChange={(e) => this.changeAddressClaimParam(e, "locality")} value={this.state.mod.parameters["address-claim"]["locality"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-locality-ph")} />
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-region">{i18next.t("admin.mod-glwd-addr-claim-region")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-region" onChange={(e) => this.changeAddressClaimParam(e, "region")} value={this.state.mod.parameters["address-claim"]["region"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-region-ph")} />
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-postal-code">{i18next.t("admin.mod-glwd-addr-claim-postal-code")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-postal-code" onChange={(e) => this.changeAddressClaimParam(e, "postal_code")} value={this.state.mod.parameters["address-claim"]["postal_code"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-postal-code-ph")} />
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-country">{i18next.t("admin.mod-glwd-addr-claim-country")}</label>
              </div>
              <input type="text" className="form-control" id="mod-glwd-addr-claim-country" onChange={(e) => this.changeAddressClaimParam(e, "country")} value={this.state.mod.parameters["address-claim"]["country"]} placeholder={i18next.t("admin.mod-glwd-addr-claim-country-ph")} />
            </div>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="mod-glwd-addr-claim-mandatory" onChange={(e) => this.toggleAddrClaimMandatory(e)} checked={this.state.mod.parameters["address-claim"].mandatory} />
            <label className="form-check-label" htmlFor="mod-glwd-addr-claim-mandatory">{i18next.t("admin.mod-glwd-addr-claim-mandatory")}</label>
          </div>
        </div>
    }

    var scopeIntrospectList = [], defaultScopeIntrospectList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeIntrospectList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, "introspection-revocation-auth-scope", scope)} disabled={!this.state.mod.parameters["introspection-revocation-allowed"]}>{scope}</a>);
        })
      }
    });

    this.state.mod.parameters["introspection-revocation-auth-scope"].forEach((scope, index) => {
      if (this.state.mod.parameters["introspection-revocation-allowed"]) {
        defaultScopeIntrospectList.push(<a className="btn-icon-right" href="#" onClick={(e) => this.deleteScope(e, "introspection-revocation-auth-scope", index)} key={index} ><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
      } else {
        defaultScopeIntrospectList.push(<span key={index} className="badge badge-primary btn-icon-right">{scope}</span>);
      }
    });
    var scopeIntrospectJsx =
      <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={!this.state.mod.parameters["introspection-revocation-allowed"]}>{i18next.t("admin.mod-glwd-scope")}</button>
        <div className="dropdown-menu" aria-labelledby="mod-register-scope">
          {scopeIntrospectList}
        </div>
        <div>
          {defaultScopeIntrospectList}
        </div>
      </div>;

    var scopeRegisterAuthList = [], defaultScopeRegisterAuthList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeRegisterAuthList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, "register-client-auth-scope", scope)} disabled={!this.state.mod.parameters["register-client-allowed"]}>{scope}</a>);
        })
      }
    });
    if (!this.state.mod.parameters["register-client-auth-scope"].length) {
      defaultScopeRegisterAuthList.push(<span key={0} className="badge badge-danger btn-icon-right">{i18next.t("admin.mod-glwd-register-client-auth-scope-open")}</span>);
    }

    this.state.mod.parameters["register-client-auth-scope"].forEach((scope, index) => {
      if (this.state.mod.parameters["register-client-allowed"]) {
        defaultScopeRegisterAuthList.push(<a className="btn-icon-right" href="#" onClick={(e) => this.deleteScope(e, "register-client-auth-scope", index)} key={index} ><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
      } else {
        defaultScopeRegisterAuthList.push(<span key={index} className="badge badge-primary btn-icon-right">{scope}</span>);
      }
    });
    var scopeRegisterClientAllowedJsx =
    <div className="dropdown">
      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={!this.state.mod.parameters["register-client-allowed"]}>{i18next.t("admin.mod-glwd-scope")}</button>
      <div className="dropdown-menu" aria-labelledby="mod-register-scope">
        {scopeRegisterAuthList}
      </div>
      <div>
        {defaultScopeRegisterAuthList}
      </div>
    </div>;

    var scopeRegisterDefaultList = [], defaultScopeRegisterDefaultList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeRegisterDefaultList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, "register-client-credentials-scope", scope)} disabled={!this.state.mod.parameters["register-client-allowed"]}>{scope}</a>);
        })
      }
    });
    this.state.mod.parameters["register-client-credentials-scope"].forEach((scope, index) => {
      if (this.state.mod.parameters["register-client-allowed"]) {
        defaultScopeRegisterDefaultList.push(<a className="btn-icon-right" href="#" onClick={(e) => this.deleteScope(e, "register-client-credentials-scope", index)} key={index} ><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
      } else {
        defaultScopeRegisterDefaultList.push(<span key={index} className="badge badge-primary btn-icon-right">{scope}</span>);
      }
    });
    var scopeRegisterClientListJsx =
      <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={!this.state.mod.parameters["register-client-allowed"]}>{i18next.t("admin.mod-glwd-scope")}</button>
        <div className="dropdown-menu" aria-labelledby="mod-register-scope">
          {scopeRegisterDefaultList}
        </div>
        <div>
          {defaultScopeRegisterDefaultList}
        </div>
      </div>;

    var resourceScopeAvailable = [];
    this.state.config.scopes.forEach((scope, index) => {
      if (this.state.mod.parameters["resource-scope"][scope.name] === undefined) {
        resourceScopeAvailable.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.setResourceScope(e, scope.name)} disabled={!this.state.mod.parameters["resource-allowed"]}>{scope.name}</a>);
      }
    });

    var resourceScopeJsx =
    <div className="btn-group" role="group">
      <button className="btn btn-secondary dropdown-toggle"
              type="button"
              id="mod-register-scope"
              data-toggle="dropdown"
              aria-haspopup="true"
              aria-expanded="false"
              disabled={!this.state.mod.parameters["resource-allowed"] || !resourceScopeAvailable.length}>
          {this.state.newResourceScope||i18next.t("admin.mod-glwd-scope")}
        </button>
      <div className="dropdown-menu" aria-labelledby="mod-register-scope">
        {resourceScopeAvailable}
      </div>
    </div>;

    var resourceScopeUrls = [];
    Object.keys(this.state.mod.parameters["resource-scope"]).forEach(scope => {
      resourceScopeUrls.push(
        <div className="form-group" key={scope}>
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <span className="input-group-text">{scope}
                <button type="button" className="close btn-icon-right" data-dismiss="alert" aria-label="Close" onClick={(e) => this.deleteResourceScope(e, scope)}>
                  <span aria-hidden="true">
                    <i className="fas fa-trash"></i>
                  </span>
                </button>
              </span>
            </div>
            <textarea className={this.state.errorList["resource-scope"]&&this.state.errorList["resource-scope"][scope]?"form-control is-invalid":"form-control"}
                      id={"mod-resource-scope-urls-"+scope}
                      onChange={(e) => this.changeResourceScopeUrls(e, scope)}
                      placeholder={i18next.t("admin.mod-glwd-resource-scope-urls-ph")}
                      value={this.state.mod.parameters["resource-scope"][scope]&&this.state.mod.parameters["resource-scope"][scope].join("\n")}>
            </textarea>
          </div>
          {this.state.errorList["resource-scope"]&&this.state.errorList["resource-scope"][scope]?<span className="error-input">{this.state.errorList["resource-scope"][scope]}</span>:""}
        </div>
      );
    });

    var rarTypes = [], i = 0;
    Object.keys(this.state.mod.parameters["rar-types"]).forEach(type => {
      var rarType = this.state.mod.parameters["rar-types"][type];

      var typeScopeAvailable = [], typeScopeAdded = [];
      this.state.config.scopes.forEach((scope, index) => {
        if (rarType.scopes.indexOf(scope.name) === -1) {
          typeScopeAvailable.push(<a key={index} 
                                     className="dropdown-item" 
                                     href="#" 
                                     onClick={(e) => this.addRarTypeScope(e, type, scope.name)} 
                                     disabled={!this.state.mod.parameters["oauth-rar-allowed"]}>
                                    {scope.name}
                                  </a>);
        } else {
          typeScopeAdded.push(
            <a href="#" onClick={(e) => this.deleteRarTypeScope(e, type, scope.name)} key={index}>
              <span className="badge badge-primary btn-icon-right">{scope.name}
                <span className="badge badge-light btn-icon-right">
                  <i className="fas fa-times"></i>
                </span>
              </span>
            </a>
          );
        }
      });

      var resourceScopeJsx =
        <div className="btn-group" role="group">
          <button className="btn btn-secondary dropdown-toggle"
                  type="button"
                  id={"mod-rar-types-scope-"+type}
                  data-toggle="dropdown"
                  aria-haspopup="true"
                  aria-expanded="false">
              {i18next.t("admin.mod-glwd-scope")}
            </button>
          <div className="dropdown-menu" aria-labelledby="mod-register-scope">
            {typeScopeAvailable}
          </div>
          {typeScopeAdded}
        </div>

      rarTypes.push(
        <div className="form-group" key={type}>
          <hr/>
          <h4>{type}</h4>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-scope-claim">{i18next.t("admin.mod-glwd-rar-scope")}</label>
              </div>
              {resourceScopeJsx}
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("admin.mod-glwd-rar-description")}
                </span>
              </div>
              <input type="text"
                     className="form-control"
                     id="mod-glwd-rar-description"
                     placeholder={i18next.t("admin.mod-glwd-rar-description-ph")}
                     value={rarType.description}
                     onChange={(e) => this.changeRarParameter(e, type, "description")}/>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("admin.mod-glwd-rar-locations")}
                </span>
              </div>
              <textarea className="form-control"
                        id={"mod-glwd-rar-locations-"+type}
                        onChange={(e) => this.changeRarParameter(e, type, "locations")}
                        placeholder={i18next.t("admin.mod-glwd-rar-locations-ph")}
                        value={rarType.locations?rarType.locations.join("\n"):""}>
              </textarea>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("admin.mod-glwd-rar-actions")}
                </span>
              </div>
              <textarea className="form-control"
                        id={"mod-glwd-rar-actions-"+type}
                        onChange={(e) => this.changeRarParameter(e, type, "actions")}
                        placeholder={i18next.t("admin.mod-glwd-rar-actions-ph")}
                        value={rarType.actions?rarType.actions.join("\n"):""}>
              </textarea>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("admin.mod-glwd-rar-datatypes")}
                </span>
              </div>
              <textarea className="form-control"
                        id={"mod-glwd-rar-datatypes-"+type}
                        onChange={(e) => this.changeRarParameter(e, type, "datatypes")}
                        placeholder={i18next.t("admin.mod-glwd-rar-datatypes-ph")}
                        value={rarType.datatypes?rarType.datatypes.join("\n"):""}>
              </textarea>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("admin.mod-glwd-rar-enriched")}
                </span>
              </div>
              <textarea className="form-control"
                        id={"mod-glwd-rar-enriched-"+type}
                        onChange={(e) => this.changeRarParameter(e, type, "enriched")}
                        placeholder={i18next.t("admin.mod-glwd-rar-enriched-ph")}
                        value={rarType.enriched?rarType.enriched.join("\n"):""}>
              </textarea>
            </div>
          </div>
          <button type="button" className="btn btn-secondary" title={i18next.t("admin.delete")} onClick={(e) => this.deleteRar(e, type)}>
            <i className="fas fa-trash"></i>
          </button>
        </div>
      );
      i++;
    });

    return (
      <div>
        <div className="form-group">
          <div>
            <div>
              <span className="input-group-text" >{i18next.t("admin.mod-glwd-url-oidc-config")}</span>
            </div>
            <code>
              {urlOidcConfig}
            </code>
          </div>
        </div>
        <div className="form-group">
          <div>
            <div>
              <span className="input-group-text" >{i18next.t("admin.mod-glwd-url-auth")}</span>
            </div>
            <code>
              {urlAuth}
            </code>
          </div>
        </div>
        <div className="form-group">
          <div>
            <div>
              <span className="input-group-text" >{i18next.t("admin.mod-glwd-url-token")}</span>
            </div>
            <code>
              {urlToken}
            </code>
          </div>
        </div>
        <div className="form-group">
          <div>
            <div>
              <span className="input-group-text" >{i18next.t("admin.mod-glwd-url-userinfo")}</span>
            </div>
            <code>
              {urlUserinfo}
            </code>
          </div>
        </div>
        <hr/>
        <div className="accordion" id="accordionGenral">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseGenral" aria-expanded="true" aria-controls="collapseAuthType">
                  {this.state.errorList["general"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-oidc-general-title")}
                </button>
              </h2>
            </div>
            <div id="collapseGenral" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionGenral">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-iss">{i18next.t("admin.mod-glwd-iss")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["iss"]?"form-control is-invalid":"form-control"} id="mod-glwd-iss" onChange={(e) => this.changeParam(e, "iss")} value={this.state.mod.parameters["iss"]} placeholder={i18next.t("admin.mod-glwd-iss-ph")} />
                  </div>
                  {this.state.errorList["iss"]?<span className="error-input">{this.state.errorList["iss"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-type">{i18next.t("admin.mod-glwd-secret-type")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-secret-type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-secret-type-" + this.state.mod.parameters["secret-type"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-secret-type">
                        <a className={"dropdown-item"+(this.state.mod.parameters["secret-type"]==="public"?" active":"")} href="#" onClick={(e) => this.changeSecretType(e, 'public')}>{i18next.t("admin.mod-glwd-secret-type-public")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["secret-type"]==="pairwise"?" active":"")} href="#" onClick={(e) => this.changeSecretType(e, 'pairwise')}>{i18next.t("admin.mod-glwd-secret-type-pairwise")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-allowed-scope">{i18next.t("admin.mod-glwd-allowed-scope")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-allowed-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-scope-select")}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-scope-claim">
                        {allowedScopeListToAdd}
                      </div>
                    </div>
                    {allowedScopeList}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionSignature">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseSignature" aria-expanded="true" aria-controls="collapseSignature">
                  {this.state.errorList["signature"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-sign-title")}
                </button>
              </h2>
            </div>
            <div id="collapseSignature" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionSignature">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <h5>{i18next.t("admin.mod-glwd-specify-jwks")}</h5>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-uri">{i18next.t("admin.mod-glwd-jwks-uri")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwks-uri" onChange={(e) => this.changeParam(e, "jwks-uri")} value={this.state.mod.parameters["jwks-uri"]} placeholder={i18next.t("admin.mod-glwd-jwks-uri-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-private">{i18next.t("admin.mod-glwd-jwks")}</label>
                    </div>
                    <div className="custom-file">
                      <input type="file" id="mod-glwd-jwks-private" className="custom-file-input" onChange={(e) => this.uploadFile(e, "jwks-private")} />
                      <label className="custom-file-label" htmlFor="mod-glwd-jwks-private">{i18next.t("admin.choose-file")}</label>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <textarea className="form-control" id="mod-glwd-jwks-private" onChange={(e) => this.changeParam(e, "jwks-private")} value={this.state.mod.parameters["jwks-private"]}></textarea>
                  </div>
                  {this.state.errorList["jwks-private"]?<span className="error-input">{this.state.errorList["jwks-private"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-public-uri">{i18next.t("admin.mod-glwd-jwks-public-uri")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwks-public-uri" onChange={(e) => this.changeParam(e, "jwks-public-uri")} value={this.state.mod.parameters["jwks-public-uri"]} placeholder={i18next.t("admin.mod-glwd-jwks-public-uri-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-public">{i18next.t("admin.mod-glwd-jwks-public")}</label>
                    </div>
                    <div className="custom-file">
                      <input type="file" id="mod-glwd-jwks-public" className="custom-file-input" onChange={(e) => this.uploadFile(e, "jwks-public")} />
                      <label className="custom-file-label" htmlFor="mod-glwd-jwks-public">{i18next.t("admin.choose-file")}</label>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <textarea className="form-control" id="mod-glwd-jwks-public" onChange={(e) => this.changeParam(e, "jwks-public")} value={this.state.mod.parameters["jwks-public"]} placeholder={i18next.t("admin.mod-glwd-jwks-public-ph")}></textarea>
                  </div>
                  {this.state.errorList["jwks-public"]?<span className="error-input">{this.state.errorList["jwks-public"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-default-kid">{i18next.t("admin.mod-glwd-default-kid")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-default-kid" onChange={(e) => this.changeParam(e, "default-kid")} value={this.state.mod.parameters["default-kid"]} placeholder={i18next.t("admin.mod-glwd-default-kid-ph")} />
                  </div>
                  {this.state.errorList["default-kid"]?<span className="error-input">{this.state.errorList["default-kid"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-client-sign_kid-parameter">{i18next.t("admin.mod-glwd-client-sign_kid-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-client-sign_kid-parameter" onChange={(e) => this.changeParam(e, "client-sign_kid-parameter")} value={this.state.mod.parameters["client-sign_kid-parameter"]} placeholder={i18next.t("admin.mod-glwd-client-sign_kid-parameter-ph")} />
                  </div>
                </div>
                <hr/>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <h5>{i18next.t("admin.mod-glwd-specify-keys")}</h5>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-type">{i18next.t("admin.mod-glwd-jwt-type")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-jwt-type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-jwt-type-" + this.state.mod.parameters["jwt-type"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-type">
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="rsa"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'rsa')}>{i18next.t("admin.mod-glwd-jwt-type-rsa")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="ecdsa"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'ecdsa')}>{i18next.t("admin.mod-glwd-jwt-type-ecdsa")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="sha"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'sha')}>{i18next.t("admin.mod-glwd-jwt-type-sha")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="rsa-pss"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'rsa-pss')}>{i18next.t("admin.mod-glwd-jwt-type-rsa-pss")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="eddsa"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'eddsa')}>{i18next.t("admin.mod-glwd-jwt-type-eddsa")}</a>
                      </div>
                    </div>
                  </div>
                  {this.state.errorList["jwt-type"]?<span className="error-input">{this.state.errorList["jwt-type"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-key-size">{i18next.t("admin.mod-glwd-jwt-key-size")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-jwt-key-size" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={this.state.mod.parameters["jwt-type"]==="eddsa"}>
                        {i18next.t("admin.mod-glwd-jwt-key-size-" + this.state.mod.parameters["jwt-key-size"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="256"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '256')}>{i18next.t("admin.mod-glwd-jwt-key-size-256")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="384"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '384')}>{i18next.t("admin.mod-glwd-jwt-key-size-384")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="512"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '512')}>{i18next.t("admin.mod-glwd-jwt-key-size-512")}</a>
                      </div>
                    </div>
                  </div>
                  {this.state.errorList["jwt-key-size"]?<span className="error-input">{this.state.errorList["jwt-key-size"]}</span>:""}
                </div>
                {keyJsx}
                {certJsx}
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionToken">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseToken" aria-expanded="true" aria-controls="collapseToken">
                  {this.state.errorList["token"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-token-title")}
                </button>
              </h2>
            </div>
            <div id="collapseToken" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionToken">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-access-token-duration">{i18next.t("admin.mod-glwd-access-token-duration")}</label>
                    </div>
                    <input type="number" min="1" step="1" className={this.state.errorList["access-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-access-token-duration" onChange={(e) => this.changeNumberParam(e, "access-token-duration")} value={this.state.mod.parameters["access-token-duration"]} placeholder={i18next.t("admin.mod-glwd-access-token-duration-ph")} />
                  </div>
                  {this.state.errorList["access-token-duration"]?<span className="error-input">{this.state.errorList["access-token-duration"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-refresh-token-duration">{i18next.t("admin.mod-glwd-refresh-token-duration")}</label>
                    </div>
                    <input type="number" min="1" step="1" className={this.state.errorList["refresh-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-refresh-token-duration" onChange={(e) => this.changeNumberParam(e, "refresh-token-duration")} value={this.state.mod.parameters["refresh-token-duration"]} placeholder={i18next.t("admin.mod-glwd-refresh-token-duration-ph")} />
                  </div>
                  {this.state.errorList["refresh-token-duration"]?<span className="error-input">{this.state.errorList["refresh-token-duration"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-code-duration">{i18next.t("admin.mod-glwd-code-duration")}</label>
                    </div>
                    <input type="number" min="1" step="1" className={this.state.errorList["code-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-code-duration" onChange={(e) => this.changeNumberParam(e, "code-duration")} value={this.state.mod.parameters["code-duration"]} placeholder={i18next.t("admin.mod-glwd-code-duration-ph")} />
                  </div>
                  {this.state.errorList["code-duration"]?<span className="error-input">{this.state.errorList["code-duration"]}</span>:""}
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-refresh-token-rolling" onChange={(e) => this.toggleParam(e, "refresh-token-rolling")} checked={this.state.mod.parameters["refresh-token-rolling"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-refresh-token-rolling">{i18next.t("admin.mod-glwd-refresh-token-rolling")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-refresh-token-one-use">{i18next.t("admin.mod-glwd-refresh-token-one-use")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-refresh-token-one-use" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-refresh-token-one-use-" + this.state.mod.parameters["refresh-token-one-use"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-refresh-token-one-use">
                        <a className={"dropdown-item"+(this.state.mod.parameters["refresh-token-one-use"]==="never"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('refresh-token-one-use', 'never')}>{i18next.t("admin.mod-glwd-refresh-token-one-use-never")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["refresh-token-one-use"]==="always"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('refresh-token-one-use', 'always')}>{i18next.t("admin.mod-glwd-refresh-token-one-use-always")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["refresh-token-one-use"]==="client-driven"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('refresh-token-one-use', 'client-driven')}>{i18next.t("admin.mod-glwd-refresh-token-one-use-client-driven")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-client-refresh-token-one-use-parameter">{i18next.t("admin.mod-glwd-client-refresh-token-one-use-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-client-refresh-token-one-use-parameter-parameter" onChange={(e) => this.changeParam(e, "client-refresh-token-one-use-parameter")} value={this.state.mod.parameters["client-refresh-token-one-use-parameter"]} placeholder={i18next.t("admin.mod-glwd-client-refresh-token-one-use-parameter-ph")} disabled={this.state.mod.parameters["refresh-token-one-use"]!=="client-driven"} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionAuthType">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAuthType" aria-expanded="true" aria-controls="collapseAuthType">
                  {this.state.errorList["token"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-auth-type-title")}
                </button>
              </h2>
            </div>
            <div id="collapseAuthType" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAuthType">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-allow-non-oidc" onChange={(e) => this.toggleParam(e, "allow-non-oidc")} checked={this.state.mod.parameters["allow-non-oidc"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-allow-non-oidc">{i18next.t("admin.mod-glwd-allow-non-oidc")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-auth-type-code-enabled" onChange={(e) => this.toggleParam(e, "auth-type-code-enabled")} checked={this.state.mod.parameters["auth-type-code-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-code-enabled">{i18next.t("admin.mod-glwd-auth-type-code-enabled")}</label>
                </div>
                <div className="form-group row">
                  <div className="col-sm-1">
                  </div>
                  <div className="col-sm-11">
                    <div className="form-check">
                      <input type="checkbox" className="form-check-input" id="mod-glwd-auth-type-code-revoke-replayed" onChange={(e) => this.toggleParam(e, "auth-type-code-revoke-replayed")} disabled={!this.state.mod.parameters["auth-type-code-enabled"]} checked={this.state.mod.parameters["auth-type-code-revoke-replayed"]} />
                      <label className="form-check-label" htmlFor="mod-glwd-auth-type-code-revoke-replayed">{i18next.t("admin.mod-glwd-auth-type-code-revoke-replayed")}</label>
                    </div>
                  </div>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-auth-type-token-enabled" onChange={(e) => this.toggleParam(e, "auth-type-token-enabled")} checked={this.state.mod.parameters["auth-type-token-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-token-enabled">{i18next.t("admin.mod-glwd-auth-type-token-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input disabled={true} type="checkbox" className="form-check-input" id="mod-glwd-auth-type-id-token-enabled" onChange={(e) => this.toggleParam(e, "auth-type-id-token-enabled")} checked={this.state.mod.parameters["auth-type-id-token-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-id-token-enabled">{i18next.t("admin.mod-glwd-auth-type-id-token-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-auth-type-none-enabled" onChange={(e) => this.toggleParam(e, "auth-type-none-enabled")} checked={this.state.mod.parameters["auth-type-none-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-none-enabled">{i18next.t("admin.mod-glwd-auth-type-none-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" disabled={!this.state.mod.parameters["allow-non-oidc"]} className="form-check-input" id="mod-glwd-auth-type-password-enabled" onChange={(e) => this.toggleParam(e, "auth-type-password-enabled")} checked={this.state.mod.parameters["auth-type-password-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-password-enabled">{i18next.t("admin.mod-glwd-auth-type-password-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" disabled={!this.state.mod.parameters["allow-non-oidc"]} className="form-check-input" id="mod-glwd-auth-type-client-enabled" onChange={(e) => this.toggleParam(e, "auth-type-client-enabled")} checked={this.state.mod.parameters["auth-type-client-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-client-enabled">{i18next.t("admin.mod-glwd-auth-type-client-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" disabled={!this.state.mod.parameters["allow-non-oidc"]} className="form-check-input" id="mod-glwd-auth-type-device-enabled" onChange={(e) => this.toggleParam(e, "auth-type-device-enabled")} checked={this.state.mod.parameters["auth-type-device-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-device-enabled">{i18next.t("admin.mod-glwd-auth-type-device-enabled")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-auth-type-refresh-enabled" onChange={(e) => this.toggleParam(e, "auth-type-refresh-enabled")} checked={this.state.mod.parameters["auth-type-refresh-enabled"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-auth-type-refresh-enabled">{i18next.t("admin.mod-glwd-auth-type-refresh-enabled")}</label>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionOpenidConfig">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseOpenidConfig" aria-expanded="true" aria-controls="collapseOpenidConfig">
                  {this.state.errorList["configuration"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-openid-configuration-title")}
                </button>
              </h2>
            </div>
            <div id="collapseOpenidConfig" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionOpenidConfig">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-service-documentation">{i18next.t("admin.mod-glwd-service-documentation")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-service-documentation" onChange={(e) => this.changeParam(e, "service-documentation")} value={this.state.mod.parameters["service-documentation"]} placeholder={i18next.t("admin.mod-glwd-service-documentation-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-op-policy-uri">{i18next.t("admin.mod-glwd-op-policy-uri")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-op-policy-uri" onChange={(e) => this.changeParam(e, "op-policy-uri")} value={this.state.mod.parameters["op-policy-uri"]} placeholder={i18next.t("admin.mod-glwd-op-policy-uri-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-op-tos-uri">{i18next.t("admin.mod-glwd-op-tos-uri")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-op-tos-uri" onChange={(e) => this.changeParam(e, "op-tos-uri")} value={this.state.mod.parameters["op-tos-uri"]} placeholder={i18next.t("admin.mod-glwd-op-tos-uri-ph")} />
                  </div>
                </div>
                <hr/>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <h5>{i18next.t("admin.mod-glwd-jwks-title")}</h5>
                    </div>
                  </div>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-jwks-show" onChange={(e) => this.toggleParam(e, "jwks-show")} checked={this.state.mod.parameters["jwks-show"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-jwks-show">{i18next.t("admin.mod-glwd-jwks-show")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-x5c">{i18next.t("admin.mod-glwd-jwks-x5c")}</label>
                    </div>
                    <div className="custom-file">
                      <input disabled={!this.state.mod.parameters["jwks-show"]} type="file" className="custom-file-input" id="mod-glwd-jwks-x5c" onChange={(e) => this.uploadX5cFile(e)} />
                      <label className="custom-file-label" htmlFor="mod-glwd-jwks-x5c">{i18next.t("admin.choose-file")}</label>
                    </div>
                  </div>
                  {x5cList}
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionScope">
          <div className="card">
            <div className="card-header" id="dataFormatCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseDataFormat" aria-expanded="true" aria-controls="collapseDataFormat">
                  {this.state.errorList["scope-override"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-scope-override")}
                </button>
              </h2>
            </div>
            <div id="collapseDataFormat" className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionScope">
              <div className="card-body">
                <p>{i18next.t("admin.mod-glwd-scope-override-message")}</p>
                <div className="btn-group" role="group">
                  <div className="btn-group" role="group">
                    {scopeJsx}
                  </div>
                  <button type="button" className="btn btn-secondary" onClick={this.addScopeOverride} title={i18next.t("admin.mod-glwd-scope-add")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
                {scopeOverrideList}
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionAddParam">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAdditionalParam" aria-expanded="true" aria-controls="collapseAdditionalParam">
                  {this.state.errorList["additional-parameters"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-additional-parameter")}
                </button>
              </h2>
            </div>
            <div id="collapseAdditionalParam" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAddParam">
              <div className="card-body">
                <p>{i18next.t("admin.mod-glwd-additional-parameter-message")}</p>
                <div className="btn-group" role="group">
                  <button type="button" className="btn btn-secondary" onClick={this.addAdditionalParameter} title={i18next.t("admin.mod-glwd-additional-parameter-add")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
                {additionalParametersList}
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionAddClaim">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAddClaim" aria-expanded="true" aria-controls="collapseAddParam">
                  {this.state.errorList["claims"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-claims")}
                </button>
              </h2>
            </div>
            <div id="collapseAddClaim" className="collapse" aria-labelledby="addClaimCard" data-parent="#accordionAddClaim">
              <div className="card-body">
                <p>{i18next.t("admin.mod-glwd-claims-message")}</p>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-name-claim">{i18next.t("admin.mod-glwd-name-claim")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-name-claim" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-claim-" + this.state.mod.parameters["name-claim"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-email-claim">
                        <a className={"dropdown-item"+(this.state.mod.parameters["name-claim"]==="no"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('name-claim', 'no')}>{i18next.t("admin.mod-glwd-name-email-claim-no")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["name-claim"]==="on-demand"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('name-claim', 'on-demand')}>{i18next.t("admin.mod-glwd-name-email-claim-on-demand")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["name-claim"]==="mandatory"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('name-claim', 'mandatory')}>{i18next.t("admin.mod-glwd-name-email-claim-mandatory")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-name-scope">{i18next.t("admin.mod-glwd-name-scope")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-name-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-scope-select")}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-scope-claim">
                        {nameScopeListToAdd}
                      </div>
                    </div>
                    {nameScopeList}
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-email-claim">{i18next.t("admin.mod-glwd-email-claim")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-email-claim" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-claim-" + this.state.mod.parameters["email-claim"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-email-claim">
                        <a className={"dropdown-item"+(this.state.mod.parameters["email-claim"]==="no"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('email-claim', 'no')}>{i18next.t("admin.mod-glwd-name-email-claim-no")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["email-claim"]==="on-demand"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('email-claim', 'on-demand')}>{i18next.t("admin.mod-glwd-name-email-claim-on-demand")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["email-claim"]==="mandatory"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('email-claim', 'mandatory')}>{i18next.t("admin.mod-glwd-name-email-claim-mandatory")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-name-scope">{i18next.t("admin.mod-glwd-email-scope")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-name-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-scope-select")}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-scope-claim">
                        {emailScopeListToAdd}
                      </div>
                    </div>
                    {emailScopeList}
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-scope-claim">{i18next.t("admin.mod-glwd-scope-claim")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-scope-claim" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-claim-" + this.state.mod.parameters["scope-claim"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-name-email-claim">
                        <a className={"dropdown-item"+(this.state.mod.parameters["scope-claim"]==="no"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('scope-claim', 'no')}>{i18next.t("admin.mod-glwd-name-email-claim-no")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["scope-claim"]==="on-demand"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('scope-claim', 'on-demand')}>{i18next.t("admin.mod-glwd-name-email-claim-on-demand")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["scope-claim"]==="mandatory"?" active":"")} href="#" onClick={(e) => this.changeParamWithValue('scope-claim', 'mandatory')}>{i18next.t("admin.mod-glwd-name-email-claim-mandatory")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-scope-scope">{i18next.t("admin.mod-glwd-scope-scope")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-scope-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-scope-select")}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-scope-scope-claim">
                        {scopeScopeListToAdd}
                      </div>
                    </div>
                    {scopeScopeList}
                  </div>
                </div>
                <div className="btn-group" role="group">
                  <button type="button" className="btn btn-secondary" onClick={this.addClaim} title={i18next.t("admin.mod-glwd-claim-add")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
                {claimsList}
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionAddressClaim">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAddressClaim" aria-expanded="true" aria-controls="collapseAddressClaim">
                  {i18next.t("admin.mod-glwd-address-claim")}
                </button>
              </h2>
            </div>
            <div id="collapseAddressClaim" className="collapse" aria-labelledby="addressClaimCard" data-parent="#accordionAddressClaim">
              <div className="card-body">
                <p>{i18next.t("admin.mod-glwd-address-claim-message")}</p>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-mod-glwd-address-claim">{i18next.t("admin.mod-glwd-address-claim-use")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-address-claim" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-name-email-claim-" + this.state.mod.parameters["address-claim"].type)}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-address-claim">
                        <a className={"dropdown-item"+(this.state.mod.parameters["address-claim"]==="no"?" active":"")} href="#" onClick={(e) => this.changeAddressClaim(e, 'no')}>{i18next.t("admin.mod-glwd-name-email-claim-no")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["address-claim"]==="on-demand"?" active":"")} href="#" onClick={(e) => this.changeAddressClaim(e, 'on-demand')}>{i18next.t("admin.mod-glwd-name-email-claim-on-demand")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["address-claim"]==="mandatory"?" active":"")} href="#" onClick={(e) => this.changeAddressClaim(e, 'mandatory')}>{i18next.t("admin.mod-glwd-name-email-claim-mandatory")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                {addressClaim}
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionJwtRequestPubkey">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseJwtRequestPubkey" aria-expanded="true" aria-controls="collapseJwtRequestPubkey">
                  {i18next.t("admin.mod-glwd-jwt-request-pubkey")}
                </button>
              </h2>
            </div>
            <div id="collapseJwtRequestPubkey" className="collapse" aria-labelledby="addressClaimCard" data-parent="#accordionJwtRequestPubkey">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-request-parameter-allow" onChange={(e) => this.toggleParam(e, "request-parameter-allow")} checked={this.state.mod.parameters["request-parameter-allow"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-request-parameter-allow">{i18next.t("admin.mod-glwd-request-parameter-allow")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-request-parameter-encryption-allow" onChange={(e) => this.toggleParam(e, "request-parameter-encryption-allow")} checked={this.state.mod.parameters["request-parameter-encryption-allow"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-request-parameter-encryption-allow">{i18next.t("admin.mod-glwd-request-parameter-encryption-allow")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-request-uri-allow-https-non-secure" onChange={(e) => this.toggleParam(e, "request-uri-allow-https-non-secure")} checked={this.state.mod.parameters["request-uri-allow-https-non-secure"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-request-uri-allow-https-non-secure">{i18next.t("admin.mod-glwd-request-uri-allow-https-non-secure")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-maximum-exp">{i18next.t("admin.mod-glwd-jwt-request-maximum-exp")}</label>
                    </div>
                    <input type="number" min="1" step="1" className="form-control" id="mod-glwd-jwt-request-maximum-exp" onChange={(e) => this.changeNumberParam(e, "request-maximum-exp", 1)} value={this.state.mod.parameters["request-maximum-exp"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-maximum-exp-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-pubkey-client-pubkey-parameter">{i18next.t("admin.mod-glwd-jwt-request-pubkey-client-pubkey-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-pubkey-client-pubkey-parameter" onChange={(e) => this.changeParam(e, "client-pubkey-parameter")} value={this.state.mod.parameters["client-pubkey-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-pubkey-client-pubkey-parameter-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-pubkey-client-jwks-parameter">{i18next.t("admin.mod-glwd-jwt-request-pubkey-client-jwks-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-pubkey-client-jwks-parameter" onChange={(e) => this.changeParam(e, "client-jwks-parameter")} value={this.state.mod.parameters["client-jwks-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-pubkey-client-jwks-parameter-ph")} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-pubkey-client-jwks_uri-parameter">{i18next.t("admin.mod-glwd-jwt-request-pubkey-client-jwks_uri-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-pubkey-client-jwks_uri-parameter" onChange={(e) => this.changeParam(e, "client-jwks_uri-parameter")} value={this.state.mod.parameters["client-jwks_uri-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-pubkey-client-jwks_uri-parameter-ph")} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionEncryptOutToken">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseEncryptOutToken" aria-expanded="true" aria-controls="collapseEncryptOutToken">
                  {i18next.t("admin.mod-glwd-jwt-request-encrypt-out-tokens")}
                </button>
              </h2>
            </div>
            <div id="collapseEncryptOutToken" className="collapse" aria-labelledby="addressClaimCard" data-parent="#accordionEncryptOutToken">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-encrypt-out-token-allow" onChange={(e) => this.toggleParam(e, "encrypt-out-token-allow")} checked={this.state.mod.parameters["encrypt-out-token-allow"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-encrypt-out-token-allow">{i18next.t("admin.mod-glwd-encrypt-out-token-allow")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-enc-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-enc-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-enc-parameter" onChange={(e) => this.changeParam(e, "client-enc-parameter")} value={this.state.mod.parameters["client-enc-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-enc-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-alg-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-alg-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-alg-parameter" onChange={(e) => this.changeParam(e, "client-alg-parameter")} value={this.state.mod.parameters["client-alg-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-alg-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-alg_kid-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-alg_kid-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-alg_kid-parameter" onChange={(e) => this.changeParam(e, "client-alg_kid-parameter")} value={this.state.mod.parameters["client-alg_kid-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-alg_kid-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_code-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_code-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_code-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_code-parameter")} value={this.state.mod.parameters["client-encrypt_code-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_code-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_at-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_at-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_at-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_at-parameter")} value={this.state.mod.parameters["client-encrypt_at-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_at-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_userinfo-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_userinfo-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_userinfo-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_userinfo-parameter")} value={this.state.mod.parameters["client-encrypt_userinfo-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_userinfo-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_id_token-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_id_token-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_id_token-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_id_token-parameter")} value={this.state.mod.parameters["client-encrypt_id_token-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_id_token-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_refresh_token-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_refresh_token-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_refresh_token-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_refresh_token-parameter")} value={this.state.mod.parameters["client-encrypt_refresh_token-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_refresh_token-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-request-client-encrypt_introspection-parameter">{i18next.t("admin.mod-glwd-jwt-request-client-encrypt_introspection-parameter")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-jwt-request-client-encrypt_introspection-parameter" onChange={(e) => this.changeParam(e, "client-encrypt_introspection-parameter")} value={this.state.mod.parameters["client-encrypt_introspection-parameter"]} placeholder={i18next.t("admin.mod-glwd-jwt-request-client-encrypt_introspection-parameter-ph")} disabled={!this.state.mod.parameters["encrypt-out-token-allow"]} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionPkce">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapsePkce" aria-expanded="true" aria-controls="collapsePkce">
                  {this.state.errorList["pkce"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-pkce-title")}
                </button>
              </h2>
            </div>
            <div id="collapsePkce" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionPkce">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-pkce-allowed" onChange={(e) => this.toggleParam(e, "pkce-allowed")} checked={this.state.mod.parameters["pkce-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-pkce-allowed">{i18next.t("admin.mod-glwd-pkce-allowed")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-pkce-method-plain-allowed" onChange={(e) => this.toggleParam(e, "pkce-method-plain-allowed")} checked={this.state.mod.parameters["pkce-method-plain-allowed"]} disabled={!this.state.mod.parameters["pkce-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-pkce-method-plain-allowed">{i18next.t("admin.mod-glwd-pkce-method-plain-allowed")}</label>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionIntrospect">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseIntrospect" aria-expanded="true" aria-controls="collapseIntrospect">
                  {this.state.errorList["introspection-revocation"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-introspection-revocation-title")}
                </button>
              </h2>
            </div>
            <div id="collapseIntrospect" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionIntrospect">
              <div className="card-body">
                {this.state.errorList["introspection-revocation"]?<span className="error-input">{i18next.t(this.state.errorList["introspection-revocation"])}</span>:""}
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-introspection-revocation-allowed" onChange={(e) => this.toggleParam(e, "introspection-revocation-allowed")} checked={this.state.mod.parameters["introspection-revocation-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-introspection-revocation-allowed">{i18next.t("admin.mod-glwd-introspection-revocation-allowed")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-introspection-revocation-allow-target-client" onChange={(e) => this.toggleParam(e, "introspection-revocation-allow-target-client")} checked={this.state.mod.parameters["introspection-revocation-allow-target-client"]} disabled={!this.state.mod.parameters["introspection-revocation-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-introspection-revocation-allow-target-client">{i18next.t("admin.mod-glwd-introspection-revocation-allow-target-client")}</label>
                </div>
                <hr/>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-glwd-introspection-revocation-scope-required")}</label>
                    </div>
                    {scopeIntrospectJsx}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionRegister">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseRegister" aria-expanded="true" aria-controls="collapseRegister">
                  {this.state.errorList["registration"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-registration-title")}
                </button>
              </h2>
            </div>
            <div id="collapseRegister" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionRegister">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-register-client-allowed" onChange={(e) => this.toggleParam(e, "register-client-allowed")} checked={this.state.mod.parameters["register-client-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-register-client-allowed">{i18next.t("admin.mod-glwd-register-client-allowed")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-glwd-register-client-auth-scope")}</label>
                    </div>
                    {scopeRegisterClientAllowedJsx}
                  </div>
                </div>
                <hr/>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-glwd-register-client-credentials-scope")}</label>
                    </div>
                    {scopeRegisterClientListJsx}
                  </div>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-register-client-management-allowed" onChange={(e) => this.toggleParam(e, "register-client-management-allowed")} checked={this.state.mod.parameters["register-client-management-allowed"]} disabled={!this.state.mod.parameters["register-client-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-register-client-management-allowed">{i18next.t("admin.mod-glwd-register-client-management-allowed")}</label>
                </div>
                <hr/>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-register-resource-specify-allowed" onChange={(e) => this.toggleParam(e, "register-resource-specify-allowed")} checked={this.state.mod.parameters["register-resource-specify-allowed"]} disabled={!this.state.mod.parameters["register-client-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-register-resource-specify-allowed">{i18next.t("admin.mod-glwd-register-resource-specify-allowed")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <span className="input-group-text">{i18next.t("admin.mod-glwd-register-resource-default")}
                      </span>
                    </div>
                    <textarea className="form-control"
                              id="mod-register-resource-default"
                              onChange={(e) => this.changeRegisterResourceDefaultUrls(e)}
                              placeholder={i18next.t("admin.mod-glwd-register-resource-default-ph")}
                              disabled={!this.state.mod.parameters["register-client-allowed"] || this.state.mod.parameters["register-resource-specify-allowed"]}
                              value={this.state.mod.parameters["register-resource-default"].join("\n")}>
                    </textarea>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionSessionManagement">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseSessionManagement" aria-expanded="true" aria-controls="collapseSessionManagement">
                  {i18next.t("admin.mod-glwd-session-management-title")}
                </button>
              </h2>
            </div>
            <div id="collapseSessionManagement" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionSessionManagement">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-session-management-allowed" onChange={(e) => this.toggleParam(e, "session-management-allowed")} checked={this.state.mod.parameters["session-management-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-session-management-allowed">{i18next.t("admin.mod-glwd-session-management-allowed")}</label>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionDeviceAuthorization">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseDeviceAuthorization" aria-expanded="true" aria-controls="collapseDeviceAuthorization">
                  {i18next.t("admin.mod-glwd-device-authorization-title")}
                </button>
              </h2>
            </div>
            <div id="collapseDeviceAuthorization" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionDeviceAuthorization">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-device-authorization-expiration">{i18next.t("admin.mod-glwd-device-authorization-expiration")}</label>
                    </div>
                    <input type="number" min="1" step="1" className="form-control" id="mod-glwd-device-authorization-expiration" onChange={(e) => this.changeNumberParam(e, "device-authorization-expiration")} value={this.state.mod.parameters["device-authorization-expiration"]} placeholder={i18next.t("admin.mod-glwd-device-authorization-expiration-ph")} disabled={!this.state.mod.parameters["auth-type-device-enabled"]} />
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-device-authorization-interval">{i18next.t("admin.mod-glwd-device-authorization-interval")}</label>
                    </div>
                    <input type="number" min="1" step="1" className="form-control" id="mod-glwd-device-authorization-interval" onChange={(e) => this.changeNumberParam(e, "device-authorization-interval")} value={this.state.mod.parameters["device-authorization-interval"]} placeholder={i18next.t("admin.mod-glwd-device-authorization-interval-ph")} disabled={!this.state.mod.parameters["auth-type-device-enabled"]} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionMtlsClient">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseMtlsClient" aria-expanded="true" aria-controls="collapseMtlsClient">
                  {i18next.t("admin.mod-glwd-mtls-client-title")}
                </button>
              </h2>
            </div>
            <div id="collapseMtlsClient" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionMtlsClient">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-mod-glwd-mtls-client-source">{i18next.t("admin.mod-glwd-mtls-client-source")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-mod-glwd-mtls-client-source" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-mtls-client-source-" + (this.state.mod.parameters["client-cert-source"]?this.state.mod.parameters["client-cert-source"]:"no"))}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-mtls-client-source">
                        <a className={"dropdown-item"+(!this.state.mod.parameters["client-cert-source"]?" active":"")} href="#" onClick={(e) => this.changeMtlsClientSource(e, false)}>{i18next.t("admin.mod-glwd-mtls-client-source-no")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["client-cert-source"]==="TLS"?" active":"")} href="#" onClick={(e) => this.changeMtlsClientSource(e, 'TLS')}>{i18next.t("admin.mod-glwd-mtls-client-source-TLS")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["client-cert-source"]==="header"?" active":"")} href="#" onClick={(e) => this.changeMtlsClientSource(e, 'header')}>{i18next.t("admin.mod-glwd-mtls-client-source-header")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["client-cert-source"]==="both"?" active":"")} href="#" onClick={(e) => this.changeMtlsClientSource(e, 'both')}>{i18next.t("admin.mod-glwd-mtls-client-source-both")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-mtls-client-cert-header-name">{i18next.t("admin.mod-glwd-mtls-client-cert-header-name")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-glwd-mtls-client-cert-header-name" onChange={(e) => this.changeParam(e, "client-cert-header-name")} value={this.state.mod.parameters["client-cert-header-name"]} placeholder={i18next.t("admin.mod-glwd-mtls-client-cert-header-name-ph")} disabled={(!this.state.mod.parameters["client-cert-source"]||this.state.mod.parameters["client-cert-source"]==="TLS")} />
                  </div>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-mtls-client-cert-use-endpoint-aliases" onChange={(e) => this.toggleParam(e, "client-cert-use-endpoint-aliases")} checked={this.state.mod.parameters["client-cert-use-endpoint-aliases"]} disabled={!this.state.mod.parameters["client-cert-source"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-mtls-client-cert-use-endpoint-aliases">{i18next.t("admin.mod-glwd-mtls-client-cert-use-endpoint-aliases")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-mtls-client-cert-self-signed-allowed" onChange={(e) => this.toggleParam(e, "client-cert-self-signed-allowed")} checked={this.state.mod.parameters["client-cert-self-signed-allowed"]} disabled={!this.state.mod.parameters["client-cert-source"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-mtls-client-cert-self-signed-allowed">{i18next.t("admin.mod-glwd-mtls-client-cert-self-signed-allowed")}</label>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionDPoP">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseDPoP" aria-expanded="true" aria-controls="collapseDPoP">
                  {this.state.errorList["oauth-dpop"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-oauth-dpop-title")}
                </button>
              </h2>
            </div>
            <div id="collapseDPoP" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionDPoP">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-glwd-oauth-dpop-allowed" onChange={(e) => this.toggleParam(e, "oauth-dpop-allowed")} checked={this.state.mod.parameters["oauth-dpop-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-oauth-dpop-allowed">{i18next.t("admin.mod-glwd-oauth-dpop-allowed")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-oauth-dpop-iat-duration">{i18next.t("admin.mod-glwd-oauth-dpop-iat-duration")}</label>
                    </div>
                    <input type="number" min="1" step="1" className="form-control" id="mod-glwd-oauth-dpop-iat-duration" onChange={(e) => this.changeNumberParam(e, "oauth-dpop-iat-duration")} value={this.state.mod.parameters["oauth-dpop-iat-duration"]} placeholder={i18next.t("admin.mod-glwd-oauth-dpop-iat-duration-ph")} disabled={!this.state.mod.parameters["oauth-dpop-allowed"]} />
                  </div>
                  {this.state.errorList["oauth-dpop-iat-duration"]?<span className="error-input">{this.state.errorList["oauth-dpop-iat-duration"]}</span>:""}
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionResource">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseResource" aria-expanded="true" aria-controls="collapseResource">
                  {this.state.errorList["resource"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-resource-title")}
                </button>
              </h2>
            </div>
            <div id="collapseResource" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionResource">
              <div className="card-body">
                {this.state.errorList["resource-scope-or-client"]?<span className="error-input">{this.state.errorList["resource-scope-or-client"]}</span>:""}
                <div className="form-group form-check">
                  <input type="checkbox"
                         className="form-check-input"
                         id="mod-glwd-resource-allowed"
                         onChange={(e) => this.toggleParam(e, "resource-allowed")}
                         checked={this.state.mod.parameters["resource-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-resource-allowed">{i18next.t("admin.mod-glwd-resource-allowed")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox"
                         className="form-check-input"
                         id="mod-glwd-resource-change-allowed"
                         onChange={(e) => this.toggleParam(e, "resource-change-allowed")}
                         checked={this.state.mod.parameters["resource-change-allowed"]}
                         disabled={!this.state.mod.parameters["resource-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-resource-change-allowed">{i18next.t("admin.mod-glwd-resource-change-allowed")}</label>
                </div>
                <div className="form-group">
                  <div className="btn-group" role="group">
                    {resourceScopeJsx}
                    <button type="button" className="btn btn-secondary" onClick={this.addResourceScope} title={i18next.t("admin.mod-glwd-resource-scope-add")} disabled={!this.state.newResourceScope || !this.state.mod.parameters["resource-allowed"]}>
                      <i className="fas fa-plus"></i>
                    </button>
                  </div>
                </div>
                <div className="form-group form-check">
                  <label className="form-check-label" htmlFor="mod-glwd-resource-allowed">{i18next.t("admin.mod-glwd-resource-scope")}</label>
                </div>
                {resourceScopeUrls}
                <div className="form-group">
                  <div className="form-check form-check-inline">
                    <input className="form-check-input"
                           type="radio"
                           id="resourceScopeAndClientFalse"
                           value={this.state.mod.parameters["resource-scope-and-client-property"]}
                           checked={!this.state.mod.parameters["resource-scope-and-client-property"]}
                           onChange={(e) => this.toggleParam(e, "resource-scope-and-client-property")}
                           disabled={!this.state.mod.parameters["resource-allowed"]} />
                    <label className="form-check-label" htmlFor="resourceScopeAndClientFalse">{i18next.t("admin.mod-glwd-resource-scope-and-client-false")}</label>
                  </div>
                  <div className="form-check form-check-inline">
                    <input className="form-check-input"
                           type="radio"
                           id="resourceScopeAndClientTrue"
                           value={this.state.mod.parameters["resource-scope-and-client-property"]}
                           checked={this.state.mod.parameters["resource-scope-and-client-property"]}
                           onChange={(e) => this.toggleParam(e, "resource-scope-and-client-property")}
                           disabled={!this.state.mod.parameters["resource-allowed"]} />
                    <label className="form-check-label" htmlFor="resourceScopeAndClientTrue">{i18next.t("admin.mod-glwd-resource-scope-and-client-true")}</label>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-resource-client-property">{i18next.t("admin.mod-glwd-resource-client-property")}</label>
                    </div>
                    <input type="text"
                           className="form-control"
                           id="mod-glwd-resource-client-property"
                           onChange={(e) => this.changeParam(e, "resource-client-property")}
                           value={this.state.mod.parameters["resource-client-property"]}
                           placeholder={i18next.t("admin.mod-glwd-resource-client-property-ph")}
                           disabled={!this.state.mod.parameters["resource-allowed"]} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionRAR">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseRAR" aria-expanded="true" aria-controls="collapseRAR">
                  {this.state.errorList["oauth-rar"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-glwd-oauth-rar-title")}
                </button>
              </h2>
            </div>
            <div id="collapseRAR" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionRAR">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox"
                         className="form-check-input"
                         id="mod-glwd-oauth-rar-allowed"
                         onChange={(e) => this.toggleParam(e, "oauth-rar-allowed")}
                         checked={this.state.mod.parameters["oauth-rar-allowed"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-oauth-rar-allowed">{i18next.t("admin.mod-glwd-oauth-rar-allowed")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox"
                         className="form-check-input"
                         id="mod-glwd-rar-allow-auth-unsigned"
                         onChange={(e) => this.toggleParam(e, "rar-allow-auth-unsigned")}
                         disabled={!this.state.mod.parameters["oauth-rar-allowed"]}
                         checked={this.state.mod.parameters["rar-allow-auth-unsigned"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-rar-allow-auth-unsigned">{i18next.t("admin.mod-glwd-rar-allow-auth-unsigned")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox"
                         className="form-check-input"
                         id="mod-glwd-rar-allow-auth-unencrypted"
                         onChange={(e) => this.toggleParam(e, "rar-allow-auth-unencrypted")}
                         disabled={!this.state.mod.parameters["oauth-rar-allowed"] || this.state.mod.parameters["rar-allow-auth-unsigned"]}
                         checked={this.state.mod.parameters["rar-allow-auth-unencrypted"]} />
                  <label className="form-check-label" htmlFor="mod-glwd-rar-allow-auth-unencrypted">{i18next.t("admin.mod-glwd-rar-allow-auth-unencrypted")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-rar-types-client-property">{i18next.t("admin.mod-glwd-rar-types-client-property")}</label>
                    </div>
                    <input type="text"
                           className="form-control"
                           id="mod-glwd-rar-types-client-property"
                           maxLength="256"
                           onChange={(e) => this.changeParam(e, "rar-types-client-property")}
                           value={this.state.mod.parameters["rar-types-client-property"]}
                           placeholder={i18next.t("admin.mod-glwd-rar-types-client-property-ph")}
                           disabled={!this.state.mod.parameters["oauth-rar-allowed"]} />
                  </div>
                  {this.state.errorList["rar-types-client-property"]?<span className="error-input">{this.state.errorList["rar-types-client-property"]}</span>:""}
                </div>
                <hr/>
                {this.state.newRarExists?<span className="error-input">{i18next.t("admin.mod-glwd-new-rar-error")}</span>:""}
                {this.state.newRarInvalidChar?<span className="error-input">{i18next.t("admin.mod-glwd-new-rar-invalid-char")}</span>:""}
                <div className="input-group mb-3">
                  <input type="text"
                         className="form-control"
                         id="mod-glwd-new-rar"
                         maxLength="256"
                         placeholder={i18next.t("admin.mod-glwd-new-rar-ph")}
                         value={this.state.newRar}
                         onChange={(e) => this.setNewRar(e)}
                         disabled={!this.state.mod.parameters["oauth-rar-allowed"]}/>
                  <div className="input-group-append">
                    <button type="button" 
                            id="mod-glwd-new-rar-btn"
                            className="btn btn-secondary" 
                            onClick={this.addRAR} 
                            title={i18next.t("admin.add")} 
                            disabled={!this.state.newRar || !this.state.mod.parameters["oauth-rar-allowed"] || this.state.newRarExists}>
                      <i className="fas fa-plus"></i>
                    </button>
                  </div>
                </div>
                {rarTypes}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default GlwdOIDCParams;
