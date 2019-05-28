import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class OTPSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      value: ""
    };
    
    this.validateMockValue = this.validateMockValue.bind(this);
    this.handleChangeMockValue = this.handleChangeMockValue.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    });
  }
  
  handleChangeMockValue(e) {
    this.setState({value: e.target.value});
  }
  
  validateMockValue(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
				value: this.state.value
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.success-value")});
      messageDispatcher.sendMessage('App', 'InitProfile');
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-value")});
    });
  }
  
  render() {
    return (
      <form action="#" id="otpSchemeForm">
        <div className="form-group">
          <h5>{i18next.t("login.otp-enter-value")}</h5>
        </div>
        <div className="form-group">
          <label htmlFor="value">{i18next.t("login.otp-value-label")}</label>
          <input type="text" className="form-control" name="value" id="value" autoFocus="" required="" placeholder={i18next.t("login.error-value-expected", {value: (this.state.triggerResult)})} value={this.state.value||""} onChange={this.handleChangeMockValue}/>
        </div>
        <button type="submit" name="but" id="but" className="btn btn-primary" onClick={(e) => this.validateMockValue(e)} title={i18next.t("login.otp-button-title")}>{i18next.t("login.btn-ok")}</button>
      </form>
    );
  }
}

export default OTPSchemeForm;
