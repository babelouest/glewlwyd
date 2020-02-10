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
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.addProvider = this.addProvider.bind(this);
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
  
  changeParam(e, param, number) {
    var mod = this.state.mod;
    if (number) {
      mod.parameters[param] = parseInt(e.target.value);
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
    mod.parameters.provider_list.push({
      name: "",
      logo_uri: "",
      logo_fa: "",
      client_id: "",
      client_secret: "",
      response_type: "code",
      userinfo_endpoint: "",
      config_endpoint: "",
      auth_endpoint: "",
      token_endpoint: "",
      userid_property: "",
      scope: "",
      additional_parameters: {},
      enabled: true
    });
    this.setState({mod: mod});
  }
  
  changeProviderParam(e, index, param) {
    var mod = this.state.mod;
    mod.parameters.provider_list[index][param] = e.target.value;
    this.setState({mod: mod});
  }
  
  checkParameters() {
  }
  
  render() {
    var providerList = [];
    this.state.mod.parameters.provider_list.forEach((provider, index) => {
      providerList.push(
        <div key={index} className="accordion" id={"accordionParams"+index}>
          <div className="card">
            <div className="card-header" id={"providerListCard"+index}>
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target={"#collapseProviderList"+index} aria-expanded="true" aria-controls={"collapseProviderList"+index}>
                  {this.state.errorList["provider_list"+index]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  <i className="fas fa-chevron-circle-down btn-icon-right"></i>
                  {provider.name}
                </button>
              </h2>
            </div>
            <div id={"collapseProviderList"+index} className="collapse" aria-labelledby={"providerListCard"+index} data-parent={"#accordionParams"+index}>
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-name">{i18next.t("admin.mod-oauth2-name")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-name"]?"form-control is-invalid":"form-control"} id="mod-oauth2-name" onChange={(e) => this.changeProviderParam(e, index, "name", 0)} value={provider.name} placeholder={i18next.t("admin.mod-oauth2-name-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-name"]?<span className="error-input">{this.state.errorList["provider-"+index+"-name"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-logo_uri">{i18next.t("admin.mod-oauth2-logo_uri")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-logo_uri"]?"form-control is-invalid":"form-control"} id="mod-oauth2-logo_uri" onChange={(e) => this.changeProviderParam(e, index, "logo_uri", 0)} value={provider.logo_uri} placeholder={i18next.t("admin.mod-oauth2-logo_uri-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-logo_uri"]?<span className="error-input">{this.state.errorList["provider-"+index+"-logo_uri"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-oauth2-logo_fa">{i18next.t("admin.mod-oauth2-logo_fa")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["provider-"+index+"-logo_fa"]?"form-control is-invalid":"form-control"} id="mod-oauth2-logo_fa" onChange={(e) => this.changeProviderParam(e, index, "logo_fa", 0)} value={provider.logo_fa} placeholder={i18next.t("admin.mod-oauth2-logo_fa-ph")}/>
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
                    <input type="text" className={this.state.errorList["provider-"+index+"-client_secret"]?"form-control is-invalid":"form-control"} id="mod-oauth2-client_secret" onChange={(e) => this.changeProviderParam(e, index, "client_secret", 0)} value={provider.client_secret} placeholder={i18next.t("admin.mod-oauth2-client_secret-ph")}/>
                  </div>
                  {this.state.errorList["provider-"+index+"-client_secret"]?<span className="error-input">{this.state.errorList["provider-"+index+"-client_secret"]}</span>:""}
                </div>
              </div>
            </div>
          </div>
        </div>
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
          <button type="button" className="btn btn-secondary" onClick={this.addProvider} title={i18next.t("admin.mod-oauth2-provider_list-add")}>
            <i className="fas fa-plus"></i>
          </button>
        </div>
        {providerList}
      </div>
    );
  }
}

export default Oauth2Params;
