import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class Oauth2SchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      providerList: []
    };
    
    this.getProviderList();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    }, () => {
      this.getProviderList();
    });
  }
  
  getProviderList() {
    if (this.state.scheme && this.state.currentUser) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {
          provider_list: true
        }
      };
      
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme, true)
      .then((res) => {
        this.setState({providerList: res});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      });
    }
  }
  
  connectProvider(provider) {
    if (this.state.scheme && this.state.currentUser) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {
          provider: provider,
          callback_url: window.location.href
        }
      };
      
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme, true)
      .then((res) => {
        document.location.href = res.redirect_to;
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      });
    }
  }
  
  render() {
    var providerList = [];
    this.state.providerList.forEach((provider, index) => {
      var logo;
      if (provider.logo_uri) {
        logo = <img src={provider.logo_uri} alt={provider.provider} />
      } else if (provider.logo_fa) {
        logo = <i className={"fab "+provider.logo_fa}></i>
      }
      providerList.push(
      <div key={index}>
        <hr/>
        <div className="row">
          <button type="button" className="btn btn-secondary" onClick={() => this.connectProvider(provider.provider)}>
            {logo}
            <span className="btn-icon-right">{i18next.t("login.oauth2-connect", {provider: provider.provider})}</span>
          </button>
        </div>
      </div>
      );
    });
    return (
      <div>
        <div className="form-group">
          <h5>{i18next.t("login.oauth2-title")}</h5>
        </div>
        <div className="form-group">
          {providerList}
        </div>
      </div>
    );
  }
}

export default Oauth2SchemeForm;
