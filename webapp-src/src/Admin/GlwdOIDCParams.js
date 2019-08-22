import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class GlwdOIDCParams extends Component {
  constructor(props) {
    super(props);
    
    props.mod.parameters?"":(props.mod.parameters = {});
    props.mod.parameters["jwt-type"]?"":(props.mod.parameters["jwt-type"] = "rsa");
    props.mod.parameters["jwt-key-size"]?"":(props.mod.parameters["jwt-key-size"] = "256");
    props.mod.parameters["key"]?"":(props.mod.parameters["key"] = "");
    props.mod.parameters["cert"]?"":(props.mod.parameters["cert"] = "");
    props.mod.parameters["cert"]?"":(props.mod.parameters["cert"] = "");
    props.mod.parameters["access-token-duration"]?"":(props.mod.parameters["access-token-duration"] = 3600);
    props.mod.parameters["refresh-token-duration"]?"":(props.mod.parameters["refresh-token-duration"] = 1209600);
    props.mod.parameters["code-duration"]?"":(props.mod.parameters["code-duration"] = 600);
    props.mod.parameters["refresh-token-rolling"]!==undefined?"":(props.mod.parameters["refresh-token-rolling"] = true);
    props.mod.parameters["allow-non-oidc"]!==undefined?"":(props.mod.parameters["allow-non-oidc"] = false);
    props.mod.parameters["auth-type-code-enabled"]!==undefined?"":(props.mod.parameters["auth-type-code-enabled"] = true);
    props.mod.parameters["auth-type-token-enabled"]!==undefined?"":(props.mod.parameters["auth-type-token-enabled"] = true);
    props.mod.parameters["auth-type-id-token-enabled"] = true;
    props.mod.parameters["auth-type-none-enabled"]!==undefined?"":(props.mod.parameters["auth-type-none-enabled"] = true);
    props.mod.parameters["auth-type-password-enabled"]!==undefined?"":(props.mod.parameters["auth-type-password-enabled"] = true);
    props.mod.parameters["auth-type-client-enabled"]!==undefined?"":(props.mod.parameters["auth-type-client-enabled"] = true);
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
    props.mod.parameters["allowed-scope"]?"":(props.mod.parameters["allowed-scope"] = ["openid"]);

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      errorList: {},
      newScopeOverride: false
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.changeParamWithValue = this.changeParamWithValue.bind(this);
    this.changeNumberParam = this.changeNumberParam.bind(this);
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
  }
  
  componentWillReceiveProps(nextProps) {
    
    nextProps.mod.parameters?"":(nextProps.mod.parameters = {});
    nextProps.mod.parameters["jwt-type"]?"":(nextProps.mod.parameters["jwt-type"] = "rsa");
    nextProps.mod.parameters["jwt-key-size"]?"":(nextProps.mod.parameters["jwt-key-size"] = "256");
    nextProps.mod.parameters["key"]?"":(nextProps.mod.parameters["key"] = "");
    nextProps.mod.parameters["cert"]?"":(nextProps.mod.parameters["cert"] = "");
    nextProps.mod.parameters["cert"]?"":(nextProps.mod.parameters["cert"] = "");
    nextProps.mod.parameters["access-token-duration"]?"":(nextProps.mod.parameters["access-token-duration"] = 3600);
    nextProps.mod.parameters["refresh-token-duration"]?"":(nextProps.mod.parameters["refresh-token-duration"] = 1209600);
    nextProps.mod.parameters["code-duration"]?"":(nextProps.mod.parameters["code-duration"] = 600);
    nextProps.mod.parameters["refresh-token-rolling"]!==undefined?"":(nextProps.mod.parameters["refresh-token-rolling"] = true);
    nextProps.mod.parameters["allow-non-oidc"]!==undefined?"":(nextProps.mod.parameters["allow-non-oidc"] = false);
    nextProps.mod.parameters["auth-type-code-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-code-enabled"] = true);
    nextProps.mod.parameters["auth-type-token-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-token-enabled"] = true);
    nextProps.mod.parameters["auth-type-id-token-enabled"] = true;
    nextProps.mod.parameters["auth-type-none-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-none-enabled"] = true);
    nextProps.mod.parameters["auth-type-password-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-password-enabled"] = true);
    nextProps.mod.parameters["auth-type-client-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-client-enabled"] = true);
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
    nextProps.mod.parameters["allowed-scope"]?"":(nextProps.mod.parameters["allowed-scope"] = ["openid"]);
    
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
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["iss"]) {
      hasError = true;
      errorList["iss"] = "admin.mod-glwd-iss-error";
    }
    if (!this.state.mod.parameters["key"]) {
      hasError = true;
      errorList["key"] = "admin.mod-glwd-key-error";
    }
    if (this.state.mod.parameters["jwt-type"] !== "sha" && !this.state.mod.parameters["cert"]) {
      hasError = true;
      errorList["cert"] = "admin.mod-glwd-cert-error";
    }
    if (!this.state.mod.parameters["access-token-duration"]) {
      hasError = true;
      errorList["access-token-duration"] = "admin.mod-glwd-access-token-duration-error";
    }
    if (!this.state.mod.parameters["refresh-token-duration"]) {
      hasError = true;
      errorList["refresh-token-duration"] = "admin.mod-glwd-refresh-token-duration-error";
    }
    if (!this.state.mod.parameters["code-duration"]) {
      hasError = true;
      errorList["code-duration"] = "admin.mod-glwd-code-duration-error";
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
        errorList["additional-parameters"][index]["user"] = "admin.mod-glwd-additional-parameter-user-parameter-error";
      }
      if (!addParam["token-parameter"]) {
        hasError = true;
        if (!errorList["additional-parameters"]) {
          errorList["additional-parameters"] = [];
        }
        if (!errorList["additional-parameters"][index]) {
          errorList["additional-parameters"][index] = {};
        }
        errorList["additional-parameters"][index]["token"] = "admin.mod-glwd-additional-parameter-token-parameter-error";
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
        errorList["additional-parameters"][index]["token"] = "admin.mod-glwd-additional-parameter-token-parameter-invalid-error";
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
        errorList["claims"][index]["name"] = "admin.mod-glwd-claims-name-error";
      } else if (["iss","sub","aud","exp","iat","auth_time","nonce","acr","amr","azp","name","email","address"].indexOf(claimParam["name"]) > -1) {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["name"] = "admin.mod-glwd-claims-name-forbidden-error";
      }
      if (claimParam["user-property"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["user-property"] = "admin.mod-glwd-claims-user-property-error";
      }
      if (claimParam["type"] === "boolean" && claimParam["boolean-value-true"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["boolean-value-true"] = "admin.mod-glwd-claims-boolean-value-true-error";
      }
      if (claimParam["type"] === "boolean" && claimParam["boolean-value-false"] === "") {
        hasError = true;
        if (!errorList["claims"]) {
          errorList["claims"] = [];
        }
        if (!errorList["claims"][index]) {
          errorList["claims"][index] = {};
        }
        errorList["claims"][index]["boolean-value-false"] = "admin.mod-glwd-claims-boolean-value-false-error";
      }
    });
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var keyJsx, certJsx, scopeOverrideList = [], scopeList = [], additionalParametersList = [], claimsList = [], x5cList = [], addressClaim;
    if (this.state.mod.parameters["jwt-type"] === "sha") {
      keyJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-glwd-key">{i18next.t("admin.mod-glwd-key")}</label>
            </div>
            <input type="password" className={this.state.errorList["key"]?"form-control is-invalid":"form-control"} id="mod-glwd-key" onChange={(e) => this.changeParam(e, "key")} value={this.state.mod.parameters["key"]} placeholder={i18next.t("admin.mod-glwd-key-ph")} />
          </div>
          {this.state.errorList["key"]?<span className="error-input">{i18next.t(this.state.errorList["key"])}</span>:""}
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
          {this.state.mod.parameters["key"]?<div className="alert alert-primary">{this.state.mod.parameters["key"].substring(0, 40)}</div>:""}
          {this.state.errorList["key"]?<span className="error-input">{i18next.t(this.state.errorList["key"])}</span>:""}
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
          {this.state.mod.parameters["cert"]?<div className="alert alert-primary">{this.state.mod.parameters["cert"].substring(0, 40)}</div>:""}
          {this.state.errorList["cert"]?<span className="error-input">{i18next.t(this.state.errorList["cert"])}</span>:""}
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
            {hasUserError?<span className="error-input">{i18next.t(this.state.errorList["additional-parameters"][index]["user"])}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-additional-parameter-token-parameter-"+parameter["token-parameter"]}>{i18next.t("admin.mod-glwd-additional-parameter-token-parameter")}</label>
            </div>
            <input type="text" className={hasTokenError?"form-control is-invalid":"form-control"} id={"mod-glwd-additional-parameter-token-parameter-"+parameter["token-parameter"]} onChange={(e) => this.setAdditionalPropertyTokenParameter(e, index)} value={parameter["token-parameter"]} placeholder={i18next.t("admin.mod-glwd-additional-parameter-token-parameter-ph")} />
          </div>
          {hasTokenError?<span className="error-input">{i18next.t(this.state.errorList["additional-parameters"][index]["token"])}</span>:""}
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
              {hasBooleanTrueError?<span className="error-input">{i18next.t(this.state.errorList["claims"][index]["boolean-value-true"])}</span>:""}
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-glwd-claims-boolean-value-false-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-boolean-value-false")}</label>
              </div>
              <input type="text" className={hasBooleanFalseError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-boolean-value-false-"+parameter["name"]} onChange={(e) => this.setClaimBooleanFalse(e, index)} value={parameter["boolean-value-false"]} placeholder={i18next.t("admin.mod-glwd-claims-boolean-value-false-ph")} />
              {hasBooleanFalseError?<span className="error-input">{i18next.t(this.state.errorList["claims"][index]["boolean-value-false"])}</span>:""}
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
            {hasNameError?<span className="error-input">{i18next.t(this.state.errorList["claims"][index]["name"])}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-glwd-claims-user-property-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-user-property")}</label>
            </div>
            <input type="text" className={hasUserPropertyError?"form-control is-invalid":"form-control"} id={"mod-glwd-claims-user-property-"+parameter["name"]} onChange={(e) => this.setClaimUserProperty(e, index)} value={parameter["user-property"]} placeholder={i18next.t("admin.mod-glwd-claims-user-property-ph")} />
            {hasUserPropertyError?<span className="error-input">{i18next.t(this.state.errorList["claims"][index]["user-property"])}</span>:""}
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
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-glwd-claims-mandatory-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-mandatory")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-glwd-claims-mandatory-"+parameter["name"]} onChange={(e) => this.toggleClaimMandatory(e, index)} checked={parameter["mandatory"]} />
              </div>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label disabled={true} className="input-group-text" htmlFor={"mod-glwd-claims-on-demand-"+parameter["name"]}>{i18next.t("admin.mod-glwd-claims-on-demand")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-glwd-claims-on-demand-"+parameter["name"]} onChange={(e) => this.toggleClaimOnDemand(e, index)} checked={parameter["on-demand"]} disabled={parameter["mandatory"]}/>
              </div>
            </div>
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
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-glwd-addr-claim-mandatory">{i18next.t("admin.mod-glwd-addr-claim-mandatory")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id="mod-glwd-addr-claim-mandatory" onChange={(e) => this.toggleAddrClaimMandatory(e)} checked={this.state.mod.parameters["address-claim"].mandatory} />
              </div>
            </div>
          </div>
        </div>
    }

    return (
      <div>
        <div className="accordion" id="accordionAuthType">
          <div className="card">
            <div className="card-header" id="addParamCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAuthType" aria-expanded="true" aria-controls="collapseAuthType">
                  {i18next.t("admin.mod-glwd-oidc-general-title")}
                </button>
              </h2>
            </div>
            <div id="collapseAuthType" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAuthType">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-iss">{i18next.t("admin.mod-glwd-iss")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["iss"]?"form-control is-invalid":"form-control"} id="mod-glwd-iss" onChange={(e) => this.changeParam(e, "iss")} value={this.state.mod.parameters["iss"]} placeholder={i18next.t("admin.mod-glwd-iss-ph")} />
                  </div>
                  {this.state.errorList["iss"]?<span className="error-input">{i18next.t(this.state.errorList["iss"])}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-request-parameter-allow">{i18next.t("admin.mod-glwd-request-parameter-allow")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-request-parameter-allow" onChange={(e) => this.toggleParam(e, "request-parameter-allow")} checked={this.state.mod.parameters["request-parameter-allow"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-request-uri-allow-https-non-secure">{i18next.t("admin.mod-glwd-request-uri-allow-https-non-secure")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-request-uri-allow-https-non-secure" onChange={(e) => this.toggleParam(e, "request-uri-allow-https-non-secure")} checked={this.state.mod.parameters["request-uri-allow-https-non-secure"]} />
                    </div>
                  </div>
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
                  {i18next.t("admin.mod-glwd-sign-title")}
                </button>
              </h2>
            </div>
            <div id="collapseSignature" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionSignature">
              <div className="card-body">
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
                      </div>
                    </div>
                  </div>
                  {this.state.errorList["jwt-type"]?<span className="error-input">{i18next.t(this.state.errorList["jwt-type"])}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwt-key-size">{i18next.t("admin.mod-glwd-jwt-key-size")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-jwt-key-size" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-glwd-jwt-key-size-" + this.state.mod.parameters["jwt-key-size"])}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="256"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '256')}>{i18next.t("admin.mod-glwd-jwt-key-size-256")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="384"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '384')}>{i18next.t("admin.mod-glwd-jwt-key-size-384")}</a>
                        <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="512"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '512')}>{i18next.t("admin.mod-glwd-jwt-key-size-512")}</a>
                      </div>
                    </div>
                  </div>
                  {this.state.errorList["jwt-key-size"]?<span className="error-input">{i18next.t(this.state.errorList["jwt-key-size"])}</span>:""}
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
                    <input type="number" min="0" step="1" className={this.state.errorList["access-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-access-token-duration" onChange={(e) => this.changeNumberParam(e, "access-token-duration")} value={this.state.mod.parameters["access-token-duration"]} placeholder={i18next.t("admin.mod-glwd-access-token-duration-ph")} />
                  </div>
                  {this.state.errorList["access-token-duration"]?<span className="error-input">{i18next.t(this.state.errorList["access-token-duration"])}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-refresh-token-duration">{i18next.t("admin.mod-glwd-refresh-token-duration")}</label>
                    </div>
                    <input type="number" min="0" step="1" className={this.state.errorList["refresh-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-refresh-token-duration" onChange={(e) => this.changeNumberParam(e, "refresh-token-duration")} value={this.state.mod.parameters["refresh-token-duration"]} placeholder={i18next.t("admin.mod-glwd-refresh-token-duration-ph")} />
                  </div>
                  {this.state.errorList["refresh-token-duration"]?<span className="error-input">{i18next.t(this.state.errorList["refresh-token-duration"])}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-code-duration">{i18next.t("admin.mod-glwd-code-duration")}</label>
                    </div>
                    <input type="number" min="0" step="1" className={this.state.errorList["code-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-code-duration" onChange={(e) => this.changeNumberParam(e, "code-duration")} value={this.state.mod.parameters["code-duration"]} placeholder={i18next.t("admin.mod-glwd-code-duration-ph")} />
                  </div>
                  {this.state.errorList["code-duration"]?<span className="error-input">{i18next.t(this.state.errorList["code-duration"])}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-refresh-token-rolling">{i18next.t("admin.mod-glwd-refresh-token-rolling")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-refresh-token-rolling" onChange={(e) => this.toggleParam(e, "refresh-token-rolling")} checked={this.state.mod.parameters["refresh-token-rolling"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-allow-non-oidc">{i18next.t("admin.mod-glwd-allow-non-oidc")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-allow-non-oidc" onChange={(e) => this.toggleParam(e, "allow-non-oidc")} checked={this.state.mod.parameters["allow-non-oidc"]} />
                    </div>
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
                  {i18next.t("admin.mod-glwd-auth-type-title")}
                </button>
              </h2>
            </div>
            <div id="collapseAuthType" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAuthType">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-code-enabled">{i18next.t("admin.mod-glwd-auth-type-code-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-auth-type-code-enabled" onChange={(e) => this.toggleParam(e, "auth-type-code-enabled")} checked={this.state.mod.parameters["auth-type-code-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-token-enabled">{i18next.t("admin.mod-glwd-auth-type-token-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-auth-type-token-enabled" onChange={(e) => this.toggleParam(e, "auth-type-token-enabled")} checked={this.state.mod.parameters["auth-type-token-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-id-token-enabled">{i18next.t("admin.mod-glwd-auth-type-id-token-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input disabled={true} type="checkbox" className="form-control" id="mod-glwd-auth-type-id-token-enabled" onChange={(e) => this.toggleParam(e, "auth-type-id-token-enabled")} checked={this.state.mod.parameters["auth-type-id-token-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-none-enabled">{i18next.t("admin.mod-glwd-auth-type-none-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-auth-type-none-enabled" onChange={(e) => this.toggleParam(e, "auth-type-none-enabled")} checked={this.state.mod.parameters["auth-type-none-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-password-enabled">{i18next.t("admin.mod-glwd-auth-type-password-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" disabled={!this.state.mod.parameters["allow-non-oidc"]} className="form-control" id="mod-glwd-auth-type-password-enabled" onChange={(e) => this.toggleParam(e, "auth-type-password-enabled")} checked={this.state.mod.parameters["auth-type-password-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-client-enabled">{i18next.t("admin.mod-glwd-auth-type-client-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" disabled={!this.state.mod.parameters["allow-non-oidc"]} className="form-control" id="mod-glwd-auth-type-client-enabled" onChange={(e) => this.toggleParam(e, "auth-type-client-enabled")} checked={this.state.mod.parameters["auth-type-client-enabled"]} />
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-auth-type-refresh-enabled">{i18next.t("admin.mod-glwd-auth-type-refresh-enabled")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-auth-type-refresh-enabled" onChange={(e) => this.toggleParam(e, "auth-type-refresh-enabled")} checked={this.state.mod.parameters["auth-type-refresh-enabled"]} />
                    </div>
                  </div>
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
                <div className="accordion" id="accordionAddParam">
                  <div className="card">
                    <div className="card-header" id="addParamCard">
                      <h2 className="mb-0">
                        <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAddParam" aria-expanded="true" aria-controls="collapseAddParam">
                        </button>
                      </h2>
                    </div>
                    <div id="collapseAddParam" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAddParam">
                      <div className="card-body">
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <h5>{i18next.t("admin.mod-glwd-jwks-title")}</h5>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-glwd-jwks-show">{i18next.t("admin.mod-glwd-jwks-show")}</label>
                    </div>
                    <div className="input-group-text">
                      <input type="checkbox" className="form-control" id="mod-glwd-jwks-show" onChange={(e) => this.toggleParam(e, "jwks-show")} checked={this.state.mod.parameters["jwks-show"]} />
                    </div>
                  </div>
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
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseAddParam" aria-expanded="true" aria-controls="collapseAddParam">
                  {i18next.t("admin.mod-glwd-additional-parameter")}
                </button>
              </h2>
            </div>
            <div id="collapseAddParam" className="collapse" aria-labelledby="addParamCard" data-parent="#accordionAddParam">
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
      </div>
    );
  }
}

export default GlwdOIDCParams;
