import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class EmailSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      code: ""
    };
    
    this.triggerScheme = this.triggerScheme.bind(this);
    this.validateCode = this.validateCode.bind(this);
    this.handleChangeCode = this.handleChangeCode.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      code: ""
    });
  }
  
  triggerScheme() {
    if (this.state.scheme && this.state.currentUser) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {}
      };
      
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme)
      .then((res) => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.mail-trigger-ok")});
      })
      .fail((err) => {
        if (err.status === 401) {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.mail-trigger-must-register")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mail-trigger")});
        }
      });
    }
  }
  
  handleChangeCode(e) {
    this.setState({code: e.target.value});
  }
  
  validateCode(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
				code: this.state.code
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('App', 'InitProfile');
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mail-value")});
    });
  }
  
  render() {
      return (
        <form action="#" id="mailSchemeForm">
          <div className="form-group">
            <h5>{i18next.t("login.enter-mail-scheme-value")}</h5>
          </div>
          <div className="form-group">
            <label htmlFor="code">{i18next.t("login.mail-value-label")}</label>
            <input type="text" className="form-control" name="code" id="code" autoFocus="" required="" placeholder={i18next.t("login.error-mail-expected")} value={this.state.code||""} onChange={this.handleChangeMockValue}/>
          </div>
          <button type="button" name="triggerbut" id="triggerbut" className="btn btn-primary" onClick={this.triggerScheme} title={i18next.t("login.mail-trugger-button-title")}>{i18next.t("login.mail-scheme-trigger")}</button>
          <button type="submit" name="mailbut" id="mailbut" className="btn btn-primary" onClick={(e) => this.validateMockValue(e)} title={i18next.t("login.mail-value-button-title")}>{i18next.t("login.btn-ok")}</button>
        </form>
      );
  }
}

export default EmailSchemeForm;
