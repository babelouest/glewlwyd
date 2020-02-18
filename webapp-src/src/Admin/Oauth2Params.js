import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class Oauth2Params extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      var urlSplitted = window.location.href.split('?')[0].split('/');
      urlSplitted[urlSplitted.length-1] = props.config.CallbackPage||'callback.html';
      props.mod = {
        parameters: {
          redirect_uri: urlSplitted.join('/'),
          session_expiration: 600,
          provider_list: []
        }
      };
    }
    
    if (props.mod.parameters.redirect_uri === undefined) {
      var urlSplitted = window.location.href.split('?')[0].split('/');
      urlSplitted[urlSplitted.length-1] = props.config.CallbackPage||'callback.html';
      props.mod.parameters.redirect_uri = urlSplitted.join('/');
    }
    
    if (props.mod.parameters.session_expiration === undefined) {
      props.mod.parameters.session_expiration = 600;
    }
    
    if (props.mod.parameters.provider_list === undefined) {
      props.mod.parameters.provider_list = [];
    }
    
    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {},
      curMainstream: -1
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.addProvider = this.addProvider.bind(this);
    this.changeMainstreamProvider = this.changeMainstreamProvider.bind(this);
    this.deleteProvider = this.deleteProvider.bind(this);
    this.changeProviderParam = this.changeProviderParam.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      var urlSplitted = window.location.href.split('?')[0].split('/');
      urlSplitted[urlSplitted.length-1] = nextProps.config.CallbackPage||'callback.html';
      nextProps.mod = {
        parameters: {
          redirect_uri: urlSplitted.join('/'),
          session_expiration: 600,
          provider_list: []
        }
      };
    }
    
    if (nextProps.mod.parameters.redirect_uri === undefined) {
      var urlSplitted = window.location.href.split('?')[0].split('/');
      urlSplitted[urlSplitted.length-1] = nextProps.config.CallbackPage||'callback.html';
      nextProps.mod.parameters.redirect_uri = urlSplitted.join('/');
    }
    
    if (nextProps.mod.parameters.session_expiration === undefined) {
      nextProps.mod.parameters.session_expiration = 600;
    }
    
    if (nextProps.mod.parameters.provider_list === undefined) {
      nextProps.mod.parameters.provider_list = [];
    }
    
    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      hasError: false,
      errorList: {}
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  changeMainstreamProvider(e, index) {
    e.preventDefault();
    this.setState({curMainstream: index});
  }
  
  changeParam(e, param, number) {
    var mod = this.state.mod;
    if (number) {
      mod.parameters[param] = parseInt(e.target.value)||0;
    } else {
      mod.parameters[param] = e.target.value;
    }
    this.setState({mod: mod});
  }
  
  toggleParam(param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }
  
  addProvider() {
    var mod = this.state.mod;
    if (this.state.curMainstream === -1) {
      mod.parameters.provider_list.push({
        name: "",
        logo_uri: "",
        logo_fa: "",
        client_id: "",
        client_secret: "",
        provider_type: "oauth2",
        response_type: "code",
        userinfo_endpoint: "",
        config_endpoint: "",
        auth_endpoint: "",
        token_endpoint: "",
        userid_property: "",
        scope: "",
        additional_parameters: [],
        enabled: true
      });
    } else {
      mod.parameters.provider_list.push(Object.assign({
        name: "",
        logo_uri: "",
        logo_fa: "",
        client_id: "",
        client_secret: "",
        provider_type: "oauth2",
        response_type: "code",
        userinfo_endpoint: "",
        config_endpoint: "",
        auth_endpoint: "",
        token_endpoint: "",
        userid_property: "",
        scope: "",
        additional_parameters: [],
        enabled: true
      },
      this.state.config.providerMainstreamList[this.state.curMainstream]));
    }
    this.setState({mod: mod});
  }
  
  deleteProvider(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list.splice(index, 1);
    this.setState({mod: mod});
  }
  
  changeProviderParam(e, index, param) {
    var mod = this.state.mod;
    mod.parameters.provider_list[index][param] = e.target.value;
    this.setState({mod: mod});
  }
  
  changeProviderType(e, index, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list[index].provider_type = value;
    this.setState({mod: mod});
  }
  
  changeResponseType(e, index, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list[index].response_type = value;
    this.setState({mod: mod});
  }
  
  addAddParam(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list[index].additional_parameters.push({key: "", value: ""});
    this.setState({mod: mod});
  }
  
  changeAddParamKey(e, index, iAddParam) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list[index].additional_parameters[iAddParam].key = e.target.value;
    this.setState({mod: mod});
  }
  
  changeAddParamValue(e, index, iAddParam) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters.provider_list[index].additional_parameters[iAddParam].value = e.target.value;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["redirect_uri"]) {
      hasError = true;
      errorList["redirect_uri"] = i18next.t("admin.mod-oauth2-redirect_uri-error");
    }
    if (!this.state.mod.parameters["session_expiration"]) {
      hasError = true;
      errorList["session_expiration"] = i18next.t("admin.mod-oauth2-session_expiration-error");
    }
    this.state.mod.parameters.provider_list.forEach((provider, index) => {
      provider.additional_parameters.forEach((curParam, iAddParam) => {
        if (!curParam.key) {
          hasError = true;
          errorList["provider-"+index+"-"+iAddParam+"-key"] = i18next.t("admin.mod-oauth2-additional_parameters-key-error");
          errorList["provider_list-"+index] = true;
        }
        if (!curParam.value) {
          hasError = true;
          errorList["provider-"+index+"-"+iAddParam+"-value"] = i18next.t("admin.mod-oauth2-additional_parameters-value-error");
          errorList["provider_list-"+index] = true;
        }
      });
      if (!provider.name) {
        hasError = true;
        errorList["provider-"+index+"-name"] = i18next.t("admin.mod-oauth2-name-error");
        errorList["provider_list-"+index] = true;
      }
      if (!provider.client_id) {
        hasError = true;
        errorList["provider-"+index+"-client_id"] = i18next.t("admin.mod-oauth2-client_id-error");
        errorList["provider_list-"+index] = true;
      }
      if (!provider.config_endpoint && !provider.userid_property) {
        hasError = true;
        errorList["provider-"+index+"-userid_property"] = i18next.t("admin.mod-oauth2-userid_property-error");
        errorList["provider_list-"+index] = true;
      }
      if (!provider.auth_endpoint && !provider.config_endpoint) {
        hasError = true;
        errorList["provider-"+index+"-auth_endpoint"] = i18next.t("admin.mod-oauth2-auth_endpoint-error");
        errorList["provider_list-"+index] = true;
      }
      if (!provider.token_endpoint && !provider.config_endpoint && provider.response_type==="code") {
        hasError = true;
        errorList["provider-"+index+"-token_endpoint"] = i18next.t("admin.mod-oauth2-token_endpoint-error");
        errorList["provider_list-"+index] = true;
      }
      if (!provider.userinfo_endpoint && !provider.config_endpoint) {
        hasError = true;
        errorList["provider-"+index+"-userinfo_endpoint"] = i18next.t("admin.mod-oauth2-userinfo_endpoint-error");
        errorList["provider_list-"+index] = true;
      }
    });
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var providerList = [], mainstreamProviders = [<a key={-1} className={"dropdown-item"+(this.state.curMainstream===-1?" active":"")} href="#" onClick={(e) => this.changeMainstreamProvider(e, -1)}>{i18next.t("admin.mod-oauth2-mainstream_provider-none")}</a>];
    this.state.mod.parameters.provider_list.forEach((provider, index) => {
      var addParam = [];
      provider.additional_parameters.forEach((curParam, iAddParam) => {
        addParam.push(
        <div key={iAddParam} className="input-group mb-3">
          <input type="text" className={this.state.errorList["provider-"+index+"-additional_parameters-"+iAddParam+"-key"]?"form-control is-invalid":"form-control"} id={"mod-oauth2-add-param-key-"+index+"-"+iAddParam} onChange={(e) => this.changeAddParamKey(e, index, iAddParam)} value={curParam.key||""} placeholder={i18next.t("admin.mod-oauth2-add-param-key-ph")}/>
          <input type="text" className={this.state.errorList["provider-"+index+"-additional_parameters-"+iAddParam+"-value"]?"form-control is-invalid":"form-control"} id={"mod-oauth2-add-param-value-"+index+"-"+iAddParam} onChange={(e) => this.changeAddParamValue(e, index, iAddParam)} value={curParam.value||""} placeholder={i18next.t("admin.mod-oauth2-add-param-value-ph")}/>
          {this.state.errorList["provider-"+index+"-"+iAddParam+"-key"]?<span className="error-input">{this.state.errorList["provider-"+index+"-"+iAddParam+"-key"]}</span>:""}
          {this.state.errorList["provider-"+index+"-"+iAddParam+"-value"]?<span className="error-input">{this.state.errorList["provider-"+index+"-"+iAddParam+"-value"]}</span>:""}
        </div>
        );
      });
      providerList.push(
        <div key={index} className="accordion" id={"accordionParams"+index}>
          <div className="card">
            <div className="card-header" id={"providerListCard"+index}>
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target={"#collapseProviderList"+index} aria-expanded="true" aria-controls={"collapseProviderList"+index}>
                  {this.state.errorList["provider_list-"+index]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  <i className="fas fa-chevron-circle-down"></i>
                  <span className="btn-icon-right">{provider.name||i18next.t("admin.mod-oauth2-new")}</span>
                </button>
                <button className="btn btn-secondary btn-sm float-right" onClick={(e) => this.deleteProvider(e, index)}>
                  <i className="fas fa-trash"></i>
                </button>
              </h2>
            </div>
            <div id={"collapseProviderList"+index} className="collapse show" aria-labelledby={"providerListCard"+index} data-parent={"#accordionParams"+index}>
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-provider_type">{i18next.t("admin.mod-oauth2-provider_type")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-oauth2-provider_type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-oauth2-provider_type-" + provider.provider_type)}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
                        <a className={"dropdown-item"+(provider.provider_type==="oauth2"?" active":"")} href="#" onClick={(e) => this.changeProviderType(e, index, 'oauth2')}>{i18next.t("admin.mod-oauth2-provider_type-oauth2")}</a>
                        <a className={"dropdown-item"+(provider.provider_type==="oidc"?" active":"")} href="#" onClick={(e) => this.changeProviderType(e, index, 'oidc')}>{i18next.t("admin.mod-oauth2-provider_type-oidc")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-name">{i18next.t("admin.mod-oauth2-name")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-name"]?"form-control is-invalid":"form-control"} id="mod-oauth2-name" onChange={(e) => this.changeProviderParam(e, index, "name", 0)} value={provider.name} placeholder={i18next.t("admin.mod-oauth2-name-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-name"]?<span className="error-input">{this.state.errorList["provider-"+index+"-name"]}</span>:""}
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-oauth2-enabled" onChange={(e) => this.toggleParam(e, index, "enabled")} checked={provider.enabled} />
                  <label className="form-check-label" htmlFor="mod-oauth2-enabled">{i18next.t("admin.mod-oauth2-enabled")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-logo_uri">{i18next.t("admin.mod-oauth2-logo_uri")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-oauth2-logo_uri" onChange={(e) => this.changeProviderParam(e, index, "logo_uri", 0)} value={provider.logo_uri} placeholder={i18next.t("admin.mod-oauth2-logo_uri-ph")}/>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-logo_fa">{i18next.t("admin.mod-oauth2-logo_fa")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-oauth2-logo_fa" onChange={(e) => this.changeProviderParam(e, index, "logo_fa", 0)} value={provider.logo_fa} placeholder={i18next.t("admin.mod-oauth2-logo_fa-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-logo_fa"]?<span className="error-input">{this.state.errorList["provider-"+index+"-logo_fa"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-client_id">{i18next.t("admin.mod-oauth2-client_id")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-client_id"]?"form-control is-invalid":"form-control"} id="mod-oauth2-client_id" onChange={(e) => this.changeProviderParam(e, index, "client_id", 0)} value={provider.client_id} placeholder={i18next.t("admin.mod-oauth2-client_id-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-client_id"]?<span className="error-input">{this.state.errorList["provider-"+index+"-client_id"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-client_secret">{i18next.t("admin.mod-oauth2-client_secret")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-oauth2-client_secret" onChange={(e) => this.changeProviderParam(e, index, "client_secret", 0)} value={provider.client_secret} placeholder={i18next.t("admin.mod-oauth2-client_secret-ph")}/>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-scope">{i18next.t("admin.mod-oauth2-scope")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-oauth2-scope" onChange={(e) => this.changeProviderParam(e, index, "scope", 0)} value={provider.scope} placeholder={i18next.t("admin.mod-oauth2-scope-ph")}/>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-response_type">{i18next.t("admin.mod-oauth2-response_type")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-oauth2-response_type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-oauth2-response_type-" + provider.response_type)}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
                        <a className={"dropdown-item"+(provider.response_type==="code"?" active":"")} href="#" onClick={(e) => this.changeResponseType(e, index, 'code')}>{i18next.t("admin.mod-oauth2-response_type-code")}</a>
                        {provider.provider_type==="oauth2"?<a className={"dropdown-item"+(provider.response_type==="token"?" active":"")} href="#" onClick={(e) => this.changeResponseType(e, index, 'token')}>{i18next.t("admin.mod-oauth2-response_type-token")}</a>:""}
                        {provider.provider_type==="oidc"?<a className={"dropdown-item"+(provider.response_type==="id_token"?" active":"")} href="#" onClick={(e) => this.changeResponseType(e, index, 'id_token')}>{i18next.t("admin.mod-oauth2-response_type-id_token")}</a>:""}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-userid_property">{i18next.t("admin.mod-oauth2-userid_property")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-userid_property"]?"form-control is-invalid":"form-control"} id="mod-oauth2-userid_property" onChange={(e) => this.changeProviderParam(e, index, "userid_property", 0)} value={provider.userid_property} placeholder={i18next.t("admin.mod-oauth2-userid_property-ph")} disabled={provider.provider_type==="oidc"}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-userid_property"]?<span className="error-input">{this.state.errorList["provider-"+index+"-userid_property"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-config_endpoint">{i18next.t("admin.mod-oauth2-config_endpoint")}</label>
                    </div>
                    <input type="text" className="form-control" id="mod-oauth2-config_endpoint" onChange={(e) => this.changeProviderParam(e, index, "config_endpoint", 0)} value={provider.config_endpoint} placeholder={i18next.t("admin.mod-oauth2-config_endpoint-ph")} disabled={provider.provider_type==="oauth2"}/>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-auth_endpoint">{i18next.t("admin.mod-oauth2-auth_endpoint")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-auth_endpoint"]?"form-control is-invalid":"form-control"} id="mod-oauth2-auth_endpoint" onChange={(e) => this.changeProviderParam(e, index, "auth_endpoint", 0)} value={provider.auth_endpoint} placeholder={i18next.t("admin.mod-oauth2-auth_endpoint-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-auth_endpoint"]?<span className="error-input">{this.state.errorList["provider-"+index+"-auth_endpoint"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-token_endpoint">{i18next.t("admin.mod-oauth2-token_endpoint")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-token_endpoint"]?"form-control is-invalid":"form-control"} id="mod-oauth2-token_endpoint" onChange={(e) => this.changeProviderParam(e, index, "token_endpoint", 0)} value={provider.token_endpoint} placeholder={i18next.t("admin.mod-oauth2-token_endpoint-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-token_endpoint"]?<span className="error-input">{this.state.errorList["provider-"+index+"-token_endpoint"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-userinfo_endpoint">{i18next.t("admin.mod-oauth2-userinfo_endpoint")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-userinfo_endpoint"]?"form-control is-invalid":"form-control"} id="mod-oauth2-userinfo_endpoint" onChange={(e) => this.changeProviderParam(e, index, "userinfo_endpoint", 0)} value={provider.userinfo_endpoint} placeholder={i18next.t("admin.mod-oauth2-userinfo_endpoint-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-userinfo_endpoint"]?<span className="error-input">{this.state.errorList["provider-"+index+"-userinfo_endpoint"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text">{i18next.t("admin.mod-oauth2-additional_parameters")}</label>
                    </div>
                    <button type="button" className="btn btn-secondary" onClick={e => this.addAddParam(e, index)} title={i18next.t("admin.mod-oauth2-additional_parameters-add")}>
                      <i className="fas fa-plus"></i>
                    </button>
                    {addParam}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    });
    this.state.config.providerMainstreamList.forEach((provider, index) => {
      mainstreamProviders.push(
        <a key={index} className={"dropdown-item"+(this.state.curMainstream===index?" active":"")} href="#" onClick={(e) => this.changeMainstreamProvider(e, index)}>{provider.name}</a>
      );
    });
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-oauth2-redirect_uri">{i18next.t("admin.mod-oauth2-redirect_uri")}</label>
            </div>
            <input type="text" className={this.state.errorList["redirect_uri"]?"form-control is-invalid":"form-control"} id="mod-oauth2-redirect_uri" onChange={(e) => this.changeParam(e, "redirect_uri", 0)} value={this.state.mod.parameters["redirect_uri"]} placeholder={i18next.t("admin.mod-oauth2-redirect_uri-ph")}/>
          </div>
          {this.state.errorList["redirect_uri"]?<span className="error-input">{this.state.errorList["redirect_uri"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-oauth2-session_expiration">{i18next.t("admin.mod-oauth2-session_expiration")}</label>
            </div>
            <input type="number" min="1" step="1" className={this.state.errorList["session_expiration"]?"form-control is-invalid":"form-control"} id="mod-oauth2-session_expiration" onChange={(e) => this.changeParam(e, "session_expiration", 1)} value={this.state.mod.parameters["session_expiration"]} placeholder={i18next.t("admin.mod-oauth2-session_expiration-ph")}/>
          </div>
          {this.state.errorList["session_expiration"]?<span className="error-input">{this.state.errorList["session_expiration"]}</span>:""}
        </div>
        <hr/>
        <div className="form-group">
          <p>{i18next.t("admin.mod-oauth2-provider_list-message")}</p>
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-oauth2-mainstream_provider" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-oauth2-mainstream_provider")}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
                {mainstreamProviders}
              </div>
            </div>
            <button type="button" className="btn btn-secondary" onClick={this.addProvider} title={i18next.t("admin.mod-oauth2-provider_list-add")}>
              <i className="fas fa-plus"></i>
            </button>
          </div>
        </div>
        {providerList}
      </div>
    );
  }
}

export default Oauth2Params;
