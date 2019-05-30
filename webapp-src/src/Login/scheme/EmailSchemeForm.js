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
      code: "",
      showValidate: false
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
      code: "",
      showValidate: false
    });
  }
  
  triggerScheme(e) {
    e.preventDefault();
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
        this.setState({showValidate: true});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.mail-trigger-error")});
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
    .fail((err) => {
      if (err.status === 401) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.mail-code-invalid")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.mail-code-error")});
      }
    });
  }
  
  render() {
    var validateButton, inputCode;
    if (this.state.showValidate) {
      validateButton = <button type="submit" name="mailbut" id="mailbut" className="btn btn-primary" onClick={(e) => this.validateCode(e)} title={i18next.t("login.mail-code-button-title")}>{i18next.t("login.btn-ok")}</button>;
      inputCode = <input type="text" className="form-control" name="code" id="code" autoFocus="" required="" placeholder={i18next.t("login.mail-code-ph")} value={this.state.code||""} onChange={this.handleChangeCode}/>;
    }
      return (
        <form action="#" id="mailSchemeForm" onSubmit={(e) => this.validateCode(e)}>
          <div className="form-group">
            <h5>{i18next.t("login.mail-enter-scheme-code")}</h5>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="code">{i18next.t("login.mail-code-label")}</label>
              </div>
              {inputCode}
            </div>
          </div>
          <div className="btn-group" role="group">
            {validateButton}
            <button type="button" name="triggerbut" id="triggerbut" className="btn btn-primary" onClick={this.triggerScheme} title={i18next.t("login.mail-trigger-button-title")}>{i18next.t("login.mail-scheme-trigger")}</button>
          </div>
        </form>
      );
  }
}

export default EmailSchemeForm;
