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
        if (err.status === 401) {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.mock-trigger-must-register")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mock-trigger")});
        }
      });
    }
  }
  
  render() {
    return (
      <form action="#" id="mockSchemeForm">
        <div className="form-group">
          <h5>{i18next.t("login.enter-mock-scheme-value")}</h5>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mockValue">{i18next.t("login.mock-value-label")}</label>
            </div>
            <input type="text" 
                   className="form-control" 
                   name="mockValue" 
                   id="mockValue" 
                   autoFocus={true} 
                   required="" 
                   placeholder={i18next.t("login.error-mock-expected", {value: (this.state.triggerResult)})} 
                   value={this.state.mockValue||""} 
                   onChange={this.handleChangeMockValue} 
                   autoComplete="false"/>
          </div>
        </div>
        <button type="submit" name="mockbut" id="mockbut" className="btn btn-primary" onClick={(e) => this.validateMockValue(e)} title={i18next.t("login.mock-value-button-title")}>{i18next.t("login.btn-ok")}</button>
      </form>
    );
  }
}

export default Oauth2SchemeForm;
