import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class PasswordSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      value: ""
    };
    
    this.validatePasswordValue = this.validatePasswordValue.bind(this);
    this.handleChangePasswordValue = this.handleChangePasswordValue.bind(this);
  }
  
  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    });
  }
  
  handleChangePasswordValue(e) {
    this.setState({value: e.target.value});
  }
  
  validatePasswordValue(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
				password: this.state.value
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.success-login")});
      messageDispatcher.sendMessage('App', {type: 'loginSuccess'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
    });
  }
  
  render() {
    return (
      <form action="#" id="otpSchemeForm">
        <div className="form-group">
          <h5>{i18next.t("login.password-enter-value")}</h5>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="value">{i18next.t("login.password-value-label")}</label>
            </div>
            <input type="password" className="form-control" name="value" id="value" autoFocus="" required="" placeholder={i18next.t("login.error-value-expected", {value: (this.state.triggerResult)})} value={this.state.value||""} onChange={this.handleChangePasswordValue}/>
          </div>
        </div>
        <button type="submit" name="but" id="but" className="btn btn-primary" onClick={(e) => this.validatePasswordValue(e)} title={i18next.t("login.password-button-title")}>{i18next.t("login.btn-ok")}</button>
      </form>
    );
  }
}

export default PasswordSchemeForm;
